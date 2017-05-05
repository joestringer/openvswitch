/*
 * Copyright (c) 2016 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include <errno.h>
#include <openvswitch/hmap.h>
#include <openvswitch/types.h>
#include <openvswitch/vlog.h>
#include <unistd.h>
#include <bpf/bpf.h>

#include "bpf.h"
#include "bpf/odp-bpf.h"
#include "dirs.h"
#include "dpif.h"
#include "dpif-provider.h"
#include "fat-rwlock.h"
#include "netdev.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "odp-util.h"
#include "ovs-numa.h"
#include "perf-event.h"
#include "poll-loop.h"

VLOG_DEFINE_THIS_MODULE(dpif_bpf);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

/* Protects against changes to 'bpf_datapaths'. */
static struct ovs_mutex bpf_datapath_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct dpif_bpf's. */
static struct shash bpf_datapaths OVS_GUARDED_BY(dp_bpf_mutex)
    = SHASH_INITIALIZER(&bpf_datapaths);

struct bpf_handler {
    /* Into owning dpif_bpf->channels */
    int offset;
    int count;
    int index;         /* next channel to use */
};

struct dpif_bpf {
    struct dpif dpif;
    const char *const name;

    /* Ports.
     *
     * Any lookup into 'ports' requires taking 'port_mutex'. */
    struct ovs_mutex port_mutex;
    struct hmap ports_by_odp OVS_GUARDED;
    struct hmap ports_by_ifindex OVS_GUARDED;
    struct seq *port_seq;       /* Incremented whenever a port changes. */
    uint64_t last_seq;

    /* Handlers */
    struct fat_rwlock upcall_lock;
    uint32_t n_handlers;
    struct bpf_handler *handlers;

    /* Upcall channels. */
    size_t page_size;
    int n_pages;
    int n_channels;
    struct perf_channel channels[];
};

struct dpif_bpf_port {
    struct hmap_node odp_node;  /* Node in dpif_bpf 'ports_by_odp'. */
    struct hmap_node if_node;   /* Node in dpif_bpf 'ports_by_ifindex'. */
    struct netdev *netdev;
    odp_port_t port_no;
    int ifindex;
    char *type;                 /* Port type as requested by user. */
    struct netdev_saved_flags *sf;

    unsigned n_rxq;
    struct netdev_rxq **rxqs;
};

int create_dpif_bpf(const char *name, struct dpif_bpf **dp);
static void dpif_bpf_close(struct dpif *dpif);
static int do_add_port(struct dpif_bpf *dp, const char *devname,
                       const char *type, odp_port_t port_no)
    OVS_REQUIRES(dp->port_mutex);
static void do_del_port(struct dpif_bpf *dpif, struct dpif_bpf_port *port)
    OVS_REQUIRES(dpif->port_mutex);

static struct dpif_bpf *
dpif_bpf_cast(const struct dpif *dpif)
{
    ovs_assert(dpif->dpif_class == &dpif_bpf_class);
    return CONTAINER_OF(dpif, struct dpif_bpf, dpif);
}

static struct dp_bpf {
    struct bpf_state bpf;
    struct netdev *outport; /* Used for downcall. */
} datapath;

static int
configure_outport(struct netdev *outport)
{
    int error;

    error = netdev_set_filter(outport, &datapath.bpf.downcall);
    if (error) {
        return error;
    }

    error = netdev_set_flags(outport, NETDEV_UP, NULL);
    if (error) {
        return error;
    }

    return 0;
}

static int
dpif_bpf_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static int error = 0;

    if (ovsthread_once_start(&once)) {
        struct netdev *outport;

        error = bpf_get(&datapath.bpf, true);
        if (!error) {
            error = netdev_open("ovs-system", "tap", &outport);
            if (!error) {
                error = configure_outport(outport);
                if (error) {
                    netdev_close(outport);
                } else {
                    datapath.outport = outport;
                }
            }
        }
        ovsthread_once_done(&once);
    }
    return error;
}

static const char
*dpif_bpf_port_open_type(const struct dpif_class *dpif_class OVS_UNUSED,
                         const char *type)
{
    return strcmp(type, "internal") ? type : "tap";
}

static int
dpif_bpf_open(const struct dpif_class *dpif_class OVS_UNUSED,
              const char *name, bool create OVS_UNUSED, struct dpif **dpifp)
{
    struct dpif_bpf *dp;
    int error;

    error = dpif_bpf_init();
    if (error) {
        VLOG_WARN("dpif_bpf_init failed");
        return error;
    }

    ovs_mutex_lock(&bpf_datapath_mutex);
    dp = shash_find_data(&bpf_datapaths, name);
    if (!dp) {
        error = create ? create_dpif_bpf(name, &dp) : ENODEV;
    } else {
        ovs_assert(dpif_class == &dpif_bpf_class);
        error = create ? EEXIST : 0;
    }
    if (!error) {
        *dpifp = &dp->dpif;
    }
    ovs_mutex_unlock(&bpf_datapath_mutex);

    return error;
}

static int
perf_event_channels_init(struct dpif_bpf *dpif)
{
    size_t length = dpif->page_size * (dpif->n_pages + 1);
    int error = 0;
    int i, cpu;

    for (cpu = 0; cpu < dpif->n_channels; cpu++) {
        struct perf_channel *channel = &dpif->channels[cpu];

        error = perf_channel_open(channel, cpu, length);
        if (error) {
            goto error;
        }
    }

error:
    if (error) {
        for (i = 0; i < cpu; i++) {
            perf_channel_close(&dpif->channels[cpu]);
        }
    }

    return error;
}

static void
dpif_bpf_free(struct dpif_bpf *dpif)
{
    shash_find_and_delete(&bpf_datapaths, dpif->name);

    ovs_mutex_destroy(&dpif->port_mutex);
    seq_destroy(dpif->port_seq);
    fat_rwlock_destroy(&dpif->upcall_lock);
    hmap_destroy(&dpif->ports_by_ifindex);
    hmap_destroy(&dpif->ports_by_odp);
    if (dpif->n_handlers) {
        free(dpif->handlers);
    }
    free(dpif);
}

int
create_dpif_bpf(const char *name, struct dpif_bpf **dp)
{
    uint16_t netflow_id = hash_string(name, 0);
    int max_cpu;
    struct dpif_bpf *dpif;
    int i, error;

    max_cpu = ovs_numa_get_n_cores();

    dpif = xzalloc(sizeof *dpif + max_cpu * sizeof(struct perf_channel));
    dpif_init(&dpif->dpif, &dpif_bpf_class, name, netflow_id >> 8, netflow_id);
    hmap_init(&dpif->ports_by_odp);
    hmap_init(&dpif->ports_by_ifindex);
    fat_rwlock_init(&dpif->upcall_lock);
    dpif->port_seq = seq_create();
    ovs_mutex_init(&dpif->port_mutex);
    dpif->n_pages = 8;
    dpif->page_size = sysconf(_SC_PAGESIZE);
    dpif->n_channels = max_cpu;
    dpif->last_seq = seq_read(dpif->port_seq);

    shash_add(&bpf_datapaths, name, dpif);

    error = perf_event_channels_init(dpif);
    if (error) {
        dpif_bpf_free(dpif);
        return error;
    }

    ovs_assert(datapath.bpf.upcalls.fd != -1);

    for (i = 0; i < dpif->n_channels; i++) {
        error = bpf_map_update_elem(datapath.bpf.upcalls.fd, &i,
                                &dpif->channels[i].fd, 0);
        if (error) {
            VLOG_WARN("failed to insert channel fd on cpu=%d: %s",
                      i, ovs_strerror(error));
            goto out;
        }
    }

out:
    if (error) {
        dpif_bpf_close(&dpif->dpif);
        dpif_bpf_free(dpif);
    }
    if (!error) {
        *dp = dpif;
    }
    return 0;
}

static void
dpif_bpf_close(struct dpif *dpif_)
{
    struct dpif_bpf *dpif = dpif_bpf_cast(dpif_);
    struct dpif_bpf_port *port, *next;
    int i;

    fat_rwlock_wrlock(&dpif->upcall_lock);
    for (i = 0; i < dpif->n_channels; i++) {
        struct perf_channel *channel = &dpif->channels[i];

        perf_channel_close(channel);
    }
    fat_rwlock_unlock(&dpif->upcall_lock);

    ovs_mutex_lock(&dpif->port_mutex);
    HMAP_FOR_EACH_SAFE (port, next, odp_node, &dpif->ports_by_odp) {
        do_del_port(dpif, port);
    }
    ovs_mutex_unlock(&dpif->port_mutex);
}

static int
dpif_bpf_destroy(struct dpif *dpif_)
{
    dpif_bpf_free(dpif_bpf_cast(dpif_));
    return 0;
}

static int
dpif_bpf_get_stats(const struct dpif *dpif OVS_UNUSED,
                   struct dpif_dp_stats *stats)
{
    uint32_t key;

    memset(stats, 0, sizeof(*stats));
    key = OVS_DP_STATS_HIT;
    if (bpf_map_lookup_elem(datapath.bpf.datapath_stats.fd, &key,
                        &stats->n_hit)) {
        VLOG_INFO("datapath_stats lookup failed (%d): %s", key,
                  ovs_strerror(errno));
    }
    key = OVS_DP_STATS_MISSED;
    if (bpf_map_lookup_elem(datapath.bpf.datapath_stats.fd, &key,
                        &stats->n_missed)) {
        VLOG_INFO("datapath_stats lookup failed (%d): %s", key,
                  ovs_strerror(errno));
    }

    /* XXX: Other missing stats */
    return 0;
}

static struct dpif_bpf_port *
bpf_lookup_port(const struct dpif_bpf *dp, odp_port_t port_no)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dpif_bpf_port *port;

    HMAP_FOR_EACH_WITH_HASH (port, odp_node, netdev_hash_port_no(port_no),
                             &dp->ports_by_odp) {
        if (port->port_no == port_no) {
            return port;
        }
    }
    return NULL;
}

static odp_port_t
choose_port(struct dpif_bpf *dp)
    OVS_REQUIRES(dp->port_mutex)
{
    uint32_t port_no;

    for (port_no = 1; port_no <= UINT16_MAX; port_no++) {
        if (!bpf_lookup_port(dp, u32_to_odp(port_no))) {
            return u32_to_odp(port_no);
        }
    }

    return ODPP_NONE;
}

static int
get_port_by_name(struct dpif_bpf *dp, const char *devname,
                 struct dpif_bpf_port **portp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dpif_bpf_port *port;

    HMAP_FOR_EACH (port, odp_node, &dp->ports_by_odp) {
        if (!strcmp(netdev_get_name(port->netdev), devname)) {
            *portp = port;
            return 0;
        }
    }

    *portp = NULL;
    return ENOENT;
}

static uint32_t
hash_ifindex(int ifindex)
{
    return hash_int(ifindex, 0);
}

static int
get_port_by_ifindex(struct dpif_bpf *dp, int ifindex,
                    struct dpif_bpf_port **portp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dpif_bpf_port *port;

    HMAP_FOR_EACH_WITH_HASH (port, if_node, hash_ifindex(ifindex),
                             &dp->ports_by_ifindex) {
        if (port->ifindex == ifindex) {
            *portp = port;
            return 0;
        }
    }

    *portp = NULL;
    return ENOENT;
}

static odp_port_t
ifindex_to_odp(struct dpif_bpf *dp, int ifindex)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dpif_bpf_port *port;

    if (get_port_by_ifindex(dp, ifindex, &port)) {
        return ODPP_NONE;
    }

    return port->port_no;
}

static bool output_to_local_stack(struct netdev *netdev)
{
    return !strcmp(netdev_get_type(netdev), "tap");
}

/* Modelled after dpif-netdev 'port_create', minus pmd and txq logic, plus
 * bpf filter set. */
static int
port_create(const char *devname, const char *type,
            odp_port_t port_no, struct dpif_bpf_port **portp)
{
    struct netdev_saved_flags *sf;
    struct dpif_bpf_port *port;
    enum netdev_flags flags;
    struct netdev *netdev;
    int n_open_rxqs = 0;
    int i, error;
    int ifindex;

    *portp = NULL;

    /* Open and validate network device. */
    error = netdev_open(devname, type, &netdev);
    if (error) {
        return error;
    }
    /* XXX reject non-Ethernet devices */

    netdev_get_flags(netdev, &flags);
    if (flags & NETDEV_LOOPBACK) {
        VLOG_ERR_RL(&rl, "%s: cannot add a loopback device", devname);
        error = EINVAL;
        goto out;
    }

    if (netdev_is_reconf_required(netdev)) {
        error = netdev_reconfigure(netdev);
        if (error) {
            goto out;
        }
    }

    ifindex = netdev_get_ifindex(netdev);
    if (ifindex < 0) {
        VLOG_WARN_RL(&rl, "%s: Failed to get ifindex", devname);
        error = -ifindex;
        goto out;
    }

    if (output_to_local_stack(netdev)) {
        error = netdev_set_filter(netdev, &datapath.bpf.egress);
    } else {
        error = netdev_set_filter(netdev, &datapath.bpf.ingress);
    }
    if (error) {
        goto out;
    }

    port = xzalloc(sizeof *port);
    port->port_no = port_no;
    port->ifindex = ifindex;
    port->netdev = netdev;
    port->n_rxq = netdev_n_rxq(netdev);
    port->rxqs = xcalloc(port->n_rxq, sizeof *port->rxqs);
    port->type = xstrdup(type);

    for (i = 0; i < port->n_rxq; i++) {
        error = netdev_rxq_open(netdev, &port->rxqs[i], i);
        if (error) {
            VLOG_ERR("%s: cannot receive packets on this network device (queue %d) (%s)",
                     devname, i, ovs_strerror(errno));
            goto out_rxq_close;
        }
        n_open_rxqs++;
    }

    error = netdev_turn_flags_on(netdev, NETDEV_PROMISC, &sf);
    if (error) {
        goto out_rxq_close;
    }
    port->sf = sf;

    *portp = port;
    return 0;

out_rxq_close:
    for (i = 0; i < n_open_rxqs; i++) {
        netdev_rxq_close(port->rxqs[i]);
    }
    free(port->type);
    free(port->rxqs);
    free(port);

out:
    netdev_close(netdev);
    return error;
}

static int
do_add_port(struct dpif_bpf *dp, const char *devname,
            const char *type, odp_port_t port_no)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dpif_bpf_port *port;
    int error;

    if (!get_port_by_name(dp, devname, &port)) {
        return EEXIST;
    }

    error = port_create(devname, type, port_no, &port);
    if (error) {
        return error;
    }

    hmap_insert(&dp->ports_by_odp, &port->odp_node,
                netdev_hash_port_no(port->port_no));
    hmap_insert(&dp->ports_by_ifindex, &port->if_node,
                hash_ifindex(port->ifindex));
    seq_change(dp->port_seq);

    return 0;
}

static int
dpif_bpf_port_add(struct dpif *dpif, struct netdev *netdev,
                  odp_port_t *port_nop)
{
    struct dpif_bpf *dp = dpif_bpf_cast(dpif);
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    const char *dpif_port;
    odp_port_t port_no;
    int error;

    ovs_mutex_lock(&dp->port_mutex);
    dpif_port = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);
    if (*port_nop != ODPP_NONE) {
        port_no = *port_nop;
        error = bpf_lookup_port(dp, *port_nop) ? EBUSY : 0;
    } else {
        port_no = choose_port(dp);
        error = port_no == ODPP_NONE ? EFBIG : 0;
    }
    if (error) {
        goto unlock;
    }

    *port_nop = port_no;
    error = do_add_port(dp, dpif_port, netdev_get_type(netdev), port_no);
    if (error) {
        goto unlock;
    }

unlock:
    ovs_mutex_unlock(&dp->port_mutex);
    return error;
}

static void
do_del_port(struct dpif_bpf *dpif, struct dpif_bpf_port *port)
    OVS_REQUIRES(dpif->port_mutex)
{
    int i, error;

    seq_change(dpif->port_seq);
    hmap_remove(&dpif->ports_by_odp, &port->odp_node);
    hmap_remove(&dpif->ports_by_ifindex, &port->if_node);

    error = netdev_set_filter(port->netdev, NULL);
    if (error) {
        VLOG_WARN("%s: Failed to clear filter from netdev",
                  netdev_get_name(port->netdev));
    }

    netdev_close(port->netdev);
    netdev_restore_flags(port->sf);
    for (i = 0; i < port->n_rxq; i++) {
        netdev_rxq_close(port->rxqs[i]);
    }

    free(port->type);
    free(port->rxqs);
    free(port);
}

static int
dpif_bpf_port_del(struct dpif *dpif, odp_port_t port_no)
{
    struct dpif_bpf *dp = dpif_bpf_cast(dpif);
    struct dpif_bpf_port *port;
    int error = 0;

    ovs_mutex_lock(&dp->port_mutex);
    port = bpf_lookup_port(dp, port_no);
    if (!port) {
        VLOG_WARN("deleting port %d, but it doesn't exist", port_no);
        error = EINVAL;
    }
    ovs_mutex_unlock(&dp->port_mutex);

    return error;
}

static void
answer_port_query(const struct dpif_bpf_port *port,
                  struct dpif_port *dpif_port)
{
    dpif_port->name = xstrdup(netdev_get_name(port->netdev));
    dpif_port->type = xstrdup(port->type);
    dpif_port->port_no = port->port_no;
}

static int
dpif_bpf_port_query_by_number(const struct dpif *dpif_, odp_port_t port_no,
                              struct dpif_port *port_)
{
    struct dpif_bpf *dpif = dpif_bpf_cast(dpif_);
    struct dpif_bpf_port *port;
    int error = 0;

    ovs_mutex_lock(&dpif->port_mutex);
    port = bpf_lookup_port(dpif, port_no);
    if (!port) {
        errno = ENOENT;
        goto out;
    }
    answer_port_query(port, port_);

out:
    ovs_mutex_unlock(&dpif->port_mutex);
    return error;
}

static int
dpif_bpf_port_query_by_name(const struct dpif *dpif_, const char *devname,
                            struct dpif_port *dpif_port)
{
    struct dpif_bpf *dpif = dpif_bpf_cast(dpif_);
    struct dpif_bpf_port *port;
    int error;

    ovs_mutex_lock(&dpif->port_mutex);
    error = get_port_by_name(dpif, devname, &port);
    if (!error && dpif_port) {
        answer_port_query(port, dpif_port);
    }
    ovs_mutex_unlock(&dpif->port_mutex);

    return error;
}

struct dpif_bpf_port_state {
    struct hmap_position position;
    char *name;
};

static int
dpif_bpf_port_dump_start(const struct dpif *dpif OVS_UNUSED, void **statep)
{
    *statep = xzalloc(sizeof(struct dpif_bpf_port_state));
    return 0;
}

static int
dpif_bpf_port_dump_next(const struct dpif *dpif_, void *state_,
                        struct dpif_port *dpif_port)
{
    struct dpif_bpf_port_state *state = state_;
    struct dpif_bpf *dpif = dpif_bpf_cast(dpif_);
    struct hmap_node *node;
    int retval;

    ovs_mutex_lock(&dpif->port_mutex);
    node = hmap_at_position(&dpif->ports_by_odp, &state->position);
    if (node) {
        struct dpif_bpf_port *port;

        port = CONTAINER_OF(node, struct dpif_bpf_port, odp_node);

        free(state->name);
        state->name = xstrdup(netdev_get_name(port->netdev));
        dpif_port->name = state->name;
        dpif_port->type = port->type;
        dpif_port->port_no = port->port_no;

        retval = 0;
    } else {
        retval = EOF;
    }
    ovs_mutex_unlock(&dpif->port_mutex);

    return retval;
}

static int
dpif_bpf_port_dump_done(const struct dpif *dpif OVS_UNUSED,
                        void *state_)
{
    struct dpif_bpf_port_state *state = state_;

    free(state->name);
    free(state);
    return 0;
}

static int
dpif_bpf_port_poll(const struct dpif *dpif_, char **devnamep OVS_UNUSED)
{
    struct dpif_bpf *dpif = dpif_bpf_cast(dpif_);
    uint64_t new_port_seq;

    new_port_seq = seq_read(dpif->port_seq);
    if (dpif->last_seq != new_port_seq) {
        dpif->last_seq = new_port_seq;
        return ENOBUFS;
    }

    return EAGAIN;
}

static void
dpif_bpf_port_poll_wait(const struct dpif *dpif_)
{
    struct dpif_bpf *dpif = dpif_bpf_cast(dpif_);

    seq_wait(dpif->port_seq, dpif->last_seq);
}

static int
dpif_bpf_flow_flush(struct dpif *dpif OVS_UNUSED)
{
    struct bpf_flow_key key;
    int err = 0;

    memset(&key, 0, sizeof key);
    do {
        err = bpf_map_get_next_key(datapath.bpf.flow_table.fd, &key, &key);
        if (!err) {
            bpf_map_delete_elem(datapath.bpf.flow_table.fd, &key);
        }
    } while (!err);

    return errno == ENOENT ? 0 : errno;
}

struct dpif_bpf_flow_dump {
    struct dpif_flow_dump up;
    int status;
    struct bpf_flow_key pos;
    struct ovs_mutex mutex;
};

static struct dpif_bpf_flow_dump *
dpif_bpf_flow_dump_cast(struct dpif_flow_dump *dump)
{
    return CONTAINER_OF(dump, struct dpif_bpf_flow_dump, up);
}

static struct dpif_flow_dump *
dpif_bpf_flow_dump_create(const struct dpif *dpif_, bool terse,
                          char *type OVS_UNUSED)
{
    struct dpif_bpf_flow_dump *dump;

    dump = xzalloc(sizeof *dump);
    dpif_flow_dump_init(&dump->up, dpif_);
    dump->up.terse = terse;
    ovs_mutex_init(&dump->mutex);

    return &dump->up;
}

static int
dpif_bpf_flow_dump_destroy(struct dpif_flow_dump *dump_)
{
    struct dpif_bpf_flow_dump *dump = dpif_bpf_flow_dump_cast(dump_);
    int status = dump->status;

    ovs_mutex_destroy(&dump->mutex);
    free(dump);

    return status == ENOENT ? 0 : status;
}

struct dpif_bpf_flow_dump_thread {
    struct dpif_flow_dump_thread up;
    struct dpif_bpf_flow_dump *dump;
};

static struct dpif_bpf_flow_dump_thread *
dpif_bpf_flow_dump_thread_cast(struct dpif_flow_dump_thread *thread)
{
    return CONTAINER_OF(thread, struct dpif_bpf_flow_dump_thread, up);
}

static struct dpif_flow_dump_thread *
dpif_bpf_flow_dump_thread_create(struct dpif_flow_dump *dump_)
{
    struct dpif_bpf_flow_dump *dump = dpif_bpf_flow_dump_cast(dump_);
    struct dpif_bpf_flow_dump_thread *thread;

    thread = xmalloc(sizeof *thread);
    dpif_flow_dump_thread_init(&thread->up, &dump->up);
    thread->dump = dump;
    return &thread->up;
}

static void
dpif_bpf_flow_dump_thread_destroy(struct dpif_flow_dump_thread *thread_)
{
    struct dpif_bpf_flow_dump_thread *thread =
        dpif_bpf_flow_dump_thread_cast(thread_);
    free(thread);
}

static int
fetch_flow(struct dpif_flow *flow OVS_UNUSED, struct bpf_flow_key *position)
{
    struct bpf_flow dp_flow OVS_UNUSED;
    struct bpf_action_batch action;
    int err;

    err = bpf_map_lookup_elem(datapath.bpf.flow_table.fd, position,
                          &action);
    if (err) {
        return errno;
    }

    /* XXX: Extract 'dp_flow' into 'flow'. */
    return EOPNOTSUPP;
}

static int
dpif_bpf_insert_flow(struct bpf_flow_key *flow_key,
                     struct bpf_action_batch *actions)
{
    int err;

    ovs_assert(datapath.bpf.flow_table.fd != -1);
    err = bpf_map_update_elem(datapath.bpf.flow_table.fd,
                              flow_key,
                              actions, BPF_ANY);
    if (err) {
        VLOG_ERR("Failed to add flow into flow table, map fd %d, error %s",
                    datapath.bpf.flow_table.fd,
                    ovs_strerror(errno));
        return errno;
    }
    return 0;
}

static int
dpif_bpf_flow_dump_next(struct dpif_flow_dump_thread *thread_,
                        struct dpif_flow *flows, int max_flows)
{
    struct dpif_bpf_flow_dump *dump =
        dpif_bpf_flow_dump_thread_cast(thread_)->dump;
    int n = 0;
    int err;

    ovs_mutex_lock(&dump->mutex);
    err = dump->status;
    if (err) {
        goto unlock;
    }

    while (n <= max_flows) {
        err = bpf_map_get_next_key(datapath.bpf.flow_table.fd,
                               &dump->pos, &dump->pos);
        if (err) {
            err = errno;
            break;
        }
        err = fetch_flow(&flows[n], &dump->pos);
        if (err == ENOENT) {
            /* Flow disappeared. Oh well, we tried. */
            continue;
        } else if (err) {
            break;
        }
        n++;
    }
    dump->status = err;
unlock:
    ovs_mutex_unlock(&dump->mutex);
    return n;
}

static int
dpif_bpf_output(struct dp_packet *packet, int ifindex, uint32_t flags)
{
    struct dp_packet_batch batch;
    struct bpf_downcall md = {
        .debug = 0xC0FFEEEE,
        .ifindex = ifindex,
        .flags = flags,
    };
    int queue = 0;
    int error;

    /* XXX: Check that ovs-system device MTU is large enough to include md. */
    dp_packet_put(packet, &md, sizeof md);
    dp_packet_batch_init_packet(&batch, packet);
    error = netdev_send(datapath.outport, queue, &batch, false, false);
    dp_packet_set_size(packet, dp_packet_size(packet) - sizeof md);

    return error;
}

static int
dpif_bpf_execute(struct dpif *dpif_, struct dpif_execute *execute)
{
    struct dpif_bpf *dpif = dpif_bpf_cast(dpif_);
    const struct nlattr *a;
    int left, error = 0;

    NL_ATTR_FOR_EACH_UNSAFE (a, left, execute->actions, execute->actions_len) {
        int type = nl_attr_type(a);

        switch(type) {
        case OVS_ACTION_ATTR_OUTPUT: {
            odp_port_t port_no = nl_attr_get_odp_port(a);
            struct dpif_bpf_port *port;
            uint32_t flags;
            int ifindex;

            ovs_mutex_lock(&dpif->port_mutex);
            port = bpf_lookup_port(dpif, port_no);
            if (port) {
                ifindex = port->ifindex;
                flags = output_to_local_stack(port->netdev)
                        ? OVS_BPF_FLAGS_TX_STACK : 0;
            }
            ovs_mutex_unlock(&dpif->port_mutex);

            if (port) {
                error = dpif_bpf_output(execute->packet, ifindex, flags);
            } else {
                VLOG_WARN_RL(&rl, "execute output on unknown port %d", port_no);
                error = ENODEV;
            }
            break;
        }
        default:
            error = EOPNOTSUPP;
            break;
        }

        if (error) {
            break;
        }

    }
    return error;
}

static void
dpif_bpf_flow_actions(struct dpif *dpif_,
                      struct bpf_action_batch *action_batch,
                      const struct nlattr *nlactions,
                      size_t actions_len)
{
    const struct nlattr *a;
    unsigned int left, count = 0;
    struct bpf_action *actions;
    struct dpif_bpf *dpif = dpif_bpf_cast(dpif_);

    memset(action_batch, 0, sizeof(*action_batch));
    actions = action_batch->actions;

    NL_ATTR_FOR_EACH_UNSAFE (a, left, nlactions, actions_len) {
        int type = nl_attr_type(a);
        actions[count].type = type;

        switch (type) {
        case OVS_ACTION_ATTR_UNSPEC:
            VLOG_ERR("unspec action");
            break;
        case OVS_ACTION_ATTR_OUTPUT: {
            struct dpif_bpf_port *port;
            odp_port_t port_no = nl_attr_get_odp_port(a);

            ovs_mutex_lock(&dpif->port_mutex);
            port = bpf_lookup_port(dpif, port_no);
            if (port) {
                VLOG_INFO("output action to port %d ifindex %d", port_no, port->ifindex);
                actions[count].u.port = port->ifindex;
            }
            ovs_mutex_unlock(&dpif->port_mutex);
            break;
        }
        default:
            VLOG_WARN("action type %d",  nl_attr_type(a));
            break;
        }
        count++;
    }

    VLOG_INFO("total number of BPF actions: %d", count);
}

static void
dpif_bpf_operate(struct dpif *dpif, struct dpif_op **ops, size_t n_ops)
{
    for (int i = 0; i < n_ops; i++) {
        struct dpif_op *op = ops[i];
        struct dpif_flow_put *put;
        struct dpif_flow_del *del OVS_UNUSED;
        struct dpif_flow_get *get OVS_UNUSED;

        struct bpf_flow_key *flow_key;

        switch (op->type) {
        case DPIF_OP_EXECUTE:
            op->error = dpif_bpf_execute(dpif, &op->u.execute);
            break;
        case DPIF_OP_FLOW_PUT: {
            int error;
            struct bpf_action_batch action_batch;

            put = &op->u.flow_put;
            flow_key = (struct bpf_flow_key *) put->key;
            dpif_bpf_flow_actions(dpif, &action_batch, put->actions, put->actions_len);

            error = dpif_bpf_insert_flow(flow_key, &action_batch);
            if (error)
                op->error = error;
            break;
        }
        case DPIF_OP_FLOW_GET:
            VLOG_INFO("get bpf_flow_key and actions");
            break;
        case DPIF_OP_FLOW_DEL:
            /* XXX: need to construct bpf_flow_key and
                    remove from flow_table map */
            VLOG_INFO("del bpf_flow_key");
            break;
        default:
            /* XXX: Implement */
            op->error = EOPNOTSUPP;
        }
    }
}

static int
dpif_bpf_recv_set(struct dpif *dpif_, bool enable)
{
    struct dpif_bpf *dpif = dpif_bpf_cast(dpif_);
    int stored_error = 0;

    for (int i = 0; i < dpif->n_channels; i++) {
        int error = perf_channel_set(&dpif->channels[i], enable);
        if (error) {
            VLOG_ERR("failed to set recv_set %s (%s)",
                     enable ? "true": "false", ovs_strerror(error));
            stored_error = error;
        }
    }

    return stored_error;
}

static int
dpif_bpf_handlers_set__(struct dpif_bpf *dpif, uint32_t n_handlers)
    OVS_REQUIRES(&dpif->upcall_lock)
{
    struct bpf_handler prev;
    int i, extra;

    memset(&prev, 0, sizeof prev);
    if (dpif->n_handlers) {
        free(dpif->handlers);
        dpif->handlers = NULL;
        dpif->n_handlers = 0;
    }

    if (!n_handlers) {
        return 0;
    }

    dpif->handlers = xzalloc(sizeof *dpif->handlers * n_handlers);
    for (i = 0; i < n_handlers; i++) {
        struct bpf_handler *curr = dpif->handlers + i;

        if (i > dpif->n_channels) {
            VLOG_INFO("Ignoring extraneous handlers (%d for %d channels)",
                      n_handlers, dpif->n_channels);
            break;
        }

        curr->offset = prev.offset + prev.count;
        curr->count = dpif->n_channels / n_handlers;
        prev = *curr;
    }
    extra = dpif->n_channels % n_handlers;
    if (extra) {
        VLOG_INFO("Extra %d channels; distributing across handlers", extra);
        for (i = 0; i < extra; i++) {
            struct bpf_handler *curr = dpif->handlers + n_handlers - i - 1;

            curr->offset = curr->offset + extra - i - 1;
            curr->count++;
        }
    }

    dpif->n_handlers = n_handlers;
    return 0;
}

static int
dpif_bpf_handlers_set(struct dpif *dpif_, uint32_t n_handlers)
{
    struct dpif_bpf *dpif = dpif_bpf_cast(dpif_);
    int error;

    fat_rwlock_wrlock(&dpif->upcall_lock);
    error = dpif_bpf_handlers_set__(dpif, n_handlers);
    fat_rwlock_unlock(&dpif->upcall_lock);

    return error;
}

static void
extract_key(struct dp_packet *packet, struct ofpbuf *buf)
{
    uint64_t key_stub[1024 / 8];
    struct ofpbuf key_buf;
    struct flow flow;
    struct odp_flow_key_parms parms = {
        .flow = &flow,
        .key_buf = &key_buf,
    };

    ofpbuf_use_stub(&key_buf, &key_stub, sizeof key_stub);
    flow_extract(packet, &flow);
    odp_flow_key_from_flow(&parms, buf);
    ofpbuf_uninit(&key_buf);
}

struct ovs_ebpf_event {
    struct perf_event_raw sample;
    struct bpf_upcall header;
    uint8_t data[];
};

/* perf_channel_read() fills the first part of 'buffer' with the full event.
 * Here, the key will be extracted immediately following it, and 'upcall'
 * will be initialized to point within 'buffer'.
 */
static int
perf_sample_to_upcall(struct dpif_bpf *dp, struct ovs_ebpf_event *e,
                      struct dpif_upcall *upcall, struct ofpbuf *buffer)
{
    size_t sample_len = e->sample.size - sizeof e->header;
    size_t pkt_len = e->header.skb_len;
    size_t pre_key_len;
    odp_port_t port_no;

    if (pkt_len < ETH_HEADER_LEN) {
        VLOG_WARN_RL(&rl, "Unexpectedly short packet (%"PRIuSIZE")", pkt_len);
        return EINVAL;
    }
    if (e->sample.size - sizeof e->header < pkt_len) {
        VLOG_WARN_RL(&rl,
            "Packet longer than sample (pkt=%"PRIuSIZE", sample=%"PRIuSIZE")",
            pkt_len, sample_len);
        return EINVAL;
    }

    port_no = ifindex_to_odp(dp, e->header.ifindex);
    if (port_no == ODPP_NONE) {
        VLOG_WARN_RL(&rl, "failed to map upcall ifindex=%d to odp",
                     e->header.ifindex);
        return EINVAL;
    }

    /* Use buffer->header to point to the packet, and buffer->msg to point to
     * the extracted flow key. */
    buffer->header = e->data;
    buffer->msg = ofpbuf_tail(buffer);

    /* XXX: Receive flow key from BPF metadata */
    pre_key_len = buffer->size;
    pkt_metadata_init(&upcall->packet.md, port_no);
    extract_key(&upcall->packet, buffer);
    ofpbuf_prealloc_tailroom(buffer, sizeof(struct bpf_downcall));
    memset(upcall, 0, sizeof *upcall);
    upcall->type = DPIF_UC_MISS;
    dp_packet_use_stub(&upcall->packet, buffer->header,
                       pkt_len + sizeof(struct bpf_downcall));
    dp_packet_set_size(&upcall->packet, pkt_len);

    // convert bpf_flow_key to nlattr
    //upcall->key = buffer->msg;
    //upcall->key_len = buffer->size - pre_key_len;
    upcall->key = (struct nlattr *) &(e->header.key);
    upcall->key_len = sizeof(struct bpf_flow_key);
    dpif_flow_hash(&dp->dpif, upcall->key, upcall->key_len, &upcall->ufid);

    return 0;
}

static void
bpf_debug_print(int subtype, int error)
{
    int level = error ? VLL_WARN : VLL_DBG;
    struct ds ds = DS_EMPTY_INITIALIZER;

    if (subtype >= 0 && subtype < ARRAY_SIZE(bpf_upcall_subtypes)) {
        ds_put_cstr(&ds, bpf_upcall_subtypes[subtype]);
    } else {
        ds_put_format(&ds, "Unknown subtype %d", subtype);
    }
    ds_put_format(&ds, " reports: %s", ovs_strerror(error));

    VLOG_RL(&rl, level, "%s", ds_cstr(&ds));
    ds_destroy(&ds);
}

static int
recv_perf_sample(struct dpif_bpf *dpif, struct ovs_ebpf_event *e,
                 struct dpif_upcall *upcall, struct ofpbuf *buffer)
{
    if (e->sample.header.size < sizeof *e
        || e->sample.size < sizeof e->header) {
        VLOG_WARN_RL(&rl, "Unexpectedly short sample (%"PRIu32")",
                     e->sample.size);
        return EINVAL;
    }

    switch (e->header.type) {
    case OVS_UPCALL_MISS:
        return perf_sample_to_upcall(dpif, e, upcall, buffer);
        break;
    case OVS_UPCALL_DEBUG:
        bpf_debug_print(e->header.subtype, e->header.error);
        return EAGAIN;
    default:
        break;
    }

    VLOG_WARN_RL(&rl, "Unfamiliar upcall type %d", e->header.type);
    return EINVAL;
}

static int
dpif_bpf_recv(struct dpif *dpif_, uint32_t handler_id,
              struct dpif_upcall *upcall, struct ofpbuf *buffer)
{
    struct dpif_bpf *dpif = dpif_bpf_cast(dpif_);
    struct bpf_handler *handler;
    int error = EAGAIN;
    int i;

    fat_rwlock_rdlock(&dpif->upcall_lock);
    handler = dpif->handlers + handler_id;
    for (i = 0; i < handler->count; i++) {
        int channel_idx = (handler->index + i) % handler->count;
        struct perf_channel *channel;

        channel = &dpif->channels[handler->offset + channel_idx];
        error = perf_channel_read(channel, buffer);
        if (!error) {
            error = recv_perf_sample(dpif, buffer->header, upcall, buffer);
        }
        if (error != EAGAIN) {
            break;
        }
    }
    handler->index = (handler->index + 1) % handler->count;
    fat_rwlock_unlock(&dpif->upcall_lock);

    return error;
}

static char *
dpif_bpf_get_datapath_version(void)
{
    return xstrdup("<built-in>");
}

static void
dpif_bpf_recv_wait(struct dpif *dpif_, uint32_t handler_id)
{
    struct dpif_bpf *dpif = dpif_bpf_cast(dpif_);
    struct bpf_handler *handler;
    int i;

    fat_rwlock_rdlock(&dpif->upcall_lock);
    handler = dpif->handlers + handler_id;
    for (i = 0; i < handler->count; i++) {
        poll_fd_wait(dpif->channels[handler->offset + i].fd, POLLIN);
    }
    fat_rwlock_unlock(&dpif->upcall_lock);
}

static void
dpif_bpf_recv_purge(struct dpif *dpif_)
{
    struct dpif_bpf *dpif = dpif_bpf_cast(dpif_);
    int i;

    fat_rwlock_rdlock(&dpif->upcall_lock);
    for (i = 0; i < dpif->n_channels; i++) {
        struct perf_channel *channel = &dpif->channels[i];

        perf_channel_flush(channel);
    }
    fat_rwlock_unlock(&dpif->upcall_lock);
}

const struct dpif_class dpif_bpf_class = {
    "bpf",
    dpif_bpf_init,
    NULL,                       /* enumerate */
    dpif_bpf_port_open_type,
    dpif_bpf_open,
    dpif_bpf_close,
    dpif_bpf_destroy,
    NULL,                       /* run */
    NULL,                       /* wait */
    dpif_bpf_get_stats,
    dpif_bpf_port_add,
    dpif_bpf_port_del,
    NULL,                       /* port_set_config */
    dpif_bpf_port_query_by_number,
    dpif_bpf_port_query_by_name,
    NULL,                       /* port_get_pid */
    dpif_bpf_port_dump_start,
    dpif_bpf_port_dump_next,
    dpif_bpf_port_dump_done,
    dpif_bpf_port_poll,
    dpif_bpf_port_poll_wait,
    dpif_bpf_flow_flush,
    dpif_bpf_flow_dump_create,
    dpif_bpf_flow_dump_destroy,
    dpif_bpf_flow_dump_thread_create,
    dpif_bpf_flow_dump_thread_destroy,
    dpif_bpf_flow_dump_next,
    dpif_bpf_operate,
    dpif_bpf_recv_set,
    dpif_bpf_handlers_set,
    NULL,                       /* set_config */
    NULL,                       /* queue_to_priority */
    dpif_bpf_recv,
    dpif_bpf_recv_wait,
    dpif_bpf_recv_purge,
    NULL,                       /* register_dp_purge_cb */
    NULL,                       /* register_upcall_cb */
    NULL,                       /* enable_upcall */
    NULL,                       /* disable_upcall */
    dpif_bpf_get_datapath_version,
    NULL,                       /* ct_dump_start */
    NULL,                       /* ct_dump_next */
    NULL,                       /* ct_dump_done */
    NULL,                       /* ct_flush */
    NULL,                       /* meter_get_features */
    NULL,                       /* meter_set */
    NULL,                       /* meter_get */
    NULL,                       /* meter_del */
};
