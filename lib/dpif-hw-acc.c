
#include <config.h>

#include "dpif-netlink.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <linux/types.h>
#include <linux/pkt_sched.h>
#include <poll.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bitmap.h"
#include "dpif-provider.h"
#include "dynamic-string.h"
#include "flow.h"
#include "fat-rwlock.h"
#include "netdev.h"
#include "netdev-linux.h"
#include "netdev-vport.h"
#include "netlink-conntrack.h"
#include "netlink-notifier.h"
#include "netlink-socket.h"
#include "netlink.h"
#include "odp-util.h"
#include "ofpbuf.h"
#include "packets.h"
#include "poll-loop.h"
#include "random.h"
#include "shash.h"
#include "sset.h"
#include "timeval.h"
#include "unaligned.h"
#include "util.h"
#include "openvswitch/vlog.h"
#include "dpif-hw-acc.h"

VLOG_DEFINE_THIS_MODULE(dpif_hw_acc);

static struct dpif_hw_acc *
dpif_hw_acc_cast(const struct dpif *dpif)
{
    dpif_assert_class(dpif, &dpif_hw_acc_class);
    return CONTAINER_OF(dpif, struct dpif_hw_acc, dpif);
}

static int
dpif_hw_acc_open(const struct dpif_class *class OVS_UNUSED,
                     const char *name, bool create, struct dpif **dpifp)
{
    struct dpif_hw_acc *dpif;
    struct dpif *lp_dpif_netlink;
    struct netdev *netdev;
    struct dpif_port dpif_port;
    struct dpif_port_dump dump;
    int error = 0;

    VLOG_DBG("%s %d %s: parameters name %s, create: %s\n", __FILE__, __LINE__,
             __func__, name, (create ? "yes" : "no"));
    if (create) {
        if ((error = dpif_create(name, "system", &lp_dpif_netlink))) {
            return error;
        }
    } else {
        if ((error = dpif_open(name, "system", &lp_dpif_netlink))) {
            return error;
        }
    }
    dpif = xzalloc(sizeof *dpif);

    *CONST_CAST(const char **, &dpif->name) = xstrdup(name);
    uint16_t netflow_id = hash_string(dpif->name, 0);

    dpif->lp_dpif_netlink = lp_dpif_netlink;

    dpif_init(&dpif->dpif, &dpif_hw_acc_class, dpif->name, netflow_id >> 8,
              netflow_id);

    *dpifp = &dpif->dpif;

    return 0;
}

static void
dpif_hw_acc_close(struct dpif *dpif_)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->close(dpif->lp_dpif_netlink);
}

static int
dpif_hw_acc_destroy(struct dpif *dpif_)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->destroy(dpif->lp_dpif_netlink);
}

static bool
dpif_hw_acc_run(struct dpif *dpif_)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->run(dpif->lp_dpif_netlink);
}

static int
dpif_hw_acc_get_stats(const struct dpif *dpif_,
                          struct dpif_dp_stats *stats)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->get_stats(dpif->lp_dpif_netlink,
                                                        stats);
}

static int
dpif_hw_acc_port_add(struct dpif *dpif_, struct netdev *netdev,
                         odp_port_t * port_nop)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->port_add(dpif->lp_dpif_netlink,
                                                       netdev, port_nop);
}

static int
dpif_hw_acc_port_del(struct dpif *dpif_, odp_port_t port_no)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->port_del(dpif->lp_dpif_netlink,
                                                       port_no);
}

static int
dpif_hw_acc_port_query_by_number(const struct dpif *dpif_,
                                     odp_port_t port_no,
                                     struct dpif_port *dpif_port)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        port_query_by_number(dpif->lp_dpif_netlink, port_no, dpif_port);
}

static int
dpif_hw_acc_port_query_by_name(const struct dpif *dpif_,
                                   const char *devname,
                                   struct dpif_port *dpif_port)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        port_query_by_name(dpif->lp_dpif_netlink, devname, dpif_port);
}

static uint32_t
dpif_hw_acc_port_get_pid(const struct dpif *dpif_, odp_port_t port_no,
                             uint32_t hash)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        port_get_pid(dpif->lp_dpif_netlink, port_no, hash);
}

static int
dpif_hw_acc_port_dump_start(const struct dpif *dpif_, void **statep)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        port_dump_start(dpif->lp_dpif_netlink, statep);
}

static int
dpif_hw_acc_port_dump_next(const struct dpif *dpif_, void *state_,
                               struct dpif_port *dpif_port)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        port_dump_next(dpif->lp_dpif_netlink, state_, dpif_port);
}

static int
dpif_hw_acc_port_dump_done(const struct dpif *dpif_ OVS_UNUSED,
                               void *state_)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        port_dump_done(dpif->lp_dpif_netlink, state_);
}

static int
dpif_hw_acc_port_poll(const struct dpif *dpif_, char **devnamep)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->port_poll(dpif->lp_dpif_netlink,
                                                        devnamep);
}

static void
dpif_hw_acc_port_poll_wait(const struct dpif *dpif_)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        port_poll_wait(dpif->lp_dpif_netlink);
}

static int
dpif_hw_acc_flow_flush(struct dpif *dpif_)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        flow_flush(dpif->lp_dpif_netlink);
}

static struct dpif_flow_dump *
dpif_hw_acc_flow_dump_create(const struct dpif *dpif_, bool terse)
{
    struct dpif_flow_dump *dump;
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    dump =
        dpif->lp_dpif_netlink->dpif_class->
        flow_dump_create(dpif->lp_dpif_netlink, terse);
    dump->dpif = CONST_CAST(struct dpif *, dpif_);

    return dump;

}

static int
dpif_hw_acc_flow_dump_destroy(struct dpif_flow_dump *dump_)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dump_->dpif);

    dump_->dpif = dpif->lp_dpif_netlink;
    return dpif->lp_dpif_netlink->dpif_class->flow_dump_destroy(dump_);
}

static struct dpif_flow_dump_thread *
dpif_hw_acc_flow_dump_thread_create(struct dpif_flow_dump *dump_)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dump_->dpif);

    return dpif->lp_dpif_netlink->dpif_class->flow_dump_thread_create(dump_);

}

static void
dpif_hw_acc_flow_dump_thread_destroy(struct dpif_flow_dump_thread *thread_)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(thread_->dpif);

    thread_->dpif = dpif->lp_dpif_netlink;
    return dpif->lp_dpif_netlink->
        dpif_class->flow_dump_thread_destroy(thread_);
}

static int
dpif_hw_acc_flow_dump_next(struct dpif_flow_dump_thread *thread_,
                               struct dpif_flow *flows, int max_flows)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(thread_->dpif);

    thread_->dpif = dpif->lp_dpif_netlink;
    return dpif->lp_dpif_netlink->dpif_class->flow_dump_next(thread_, flows,
                                                             max_flows);
}

static void
dpif_hw_acc_operate(struct dpif *dpif_, struct dpif_op **ops, size_t n_ops)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->operate(dpif->lp_dpif_netlink,
                                                      ops, n_ops);
}

static int
dpif_hw_acc_recv_set(struct dpif *dpif_, bool enable)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->recv_set(dpif->lp_dpif_netlink,
                                                       enable);
}

static int
dpif_hw_acc_handlers_set(struct dpif *dpif_, uint32_t n_handlers)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        handlers_set(dpif->lp_dpif_netlink, n_handlers);
}

static int
dpif_hw_acc_queue_to_priority(const struct dpif *dpif_,
                                  uint32_t queue_id, uint32_t * priority)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        queue_to_priority(dpif->lp_dpif_netlink, queue_id, priority);
}

static int
dpif_hw_acc_recv(struct dpif *dpif_, uint32_t handler_id,
                     struct dpif_upcall *upcall, struct ofpbuf *buf)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->recv(dpif->lp_dpif_netlink,
                                                   handler_id, upcall, buf);

}

static void
dpif_hw_acc_recv_wait(struct dpif *dpif_, uint32_t handler_id)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->recv_wait(dpif->lp_dpif_netlink,
                                                        handler_id);
}

static void
dpif_hw_acc_recv_purge(struct dpif *dpif_)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        recv_purge(dpif->lp_dpif_netlink);
}

static int
dpif_hw_acc_ct_dump_start(struct dpif *dpif_,
                              struct ct_dpif_dump_state **dump_,
                              const uint16_t * zone)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        ct_dump_start(dpif->lp_dpif_netlink, dump_, zone);
}

static int
dpif_hw_acc_ct_dump_next(struct dpif *dpif_,
                             struct ct_dpif_dump_state *dump_,
                             struct ct_dpif_entry *entry)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        ct_dump_next(dpif->lp_dpif_netlink, dump_, entry);
}

static int
dpif_hw_acc_ct_dump_done(struct dpif *dpif_,
                             struct ct_dpif_dump_state *dump_)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->
        ct_dump_done(dpif->lp_dpif_netlink, dump_);
}

static int
dpif_hw_acc_ct_flush(struct dpif *dpif_, const uint16_t * zone)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    return dpif->lp_dpif_netlink->dpif_class->ct_flush(dpif->lp_dpif_netlink,
                                                       zone);
}

const struct dpif_class dpif_hw_acc_class = {
    "hw_netlink",
    NULL,                       /* init */
    NULL,
    NULL,
    dpif_hw_acc_open,
    dpif_hw_acc_close,
    dpif_hw_acc_destroy,
    dpif_hw_acc_run,
    NULL,                       /* wait */
    dpif_hw_acc_get_stats,
    dpif_hw_acc_port_add,
    dpif_hw_acc_port_del,
    dpif_hw_acc_port_query_by_number,
    dpif_hw_acc_port_query_by_name,
    dpif_hw_acc_port_get_pid,
    dpif_hw_acc_port_dump_start,
    dpif_hw_acc_port_dump_next,
    dpif_hw_acc_port_dump_done,
    dpif_hw_acc_port_poll,
    dpif_hw_acc_port_poll_wait,
    dpif_hw_acc_flow_flush,
    dpif_hw_acc_flow_dump_create,
    dpif_hw_acc_flow_dump_destroy,
    dpif_hw_acc_flow_dump_thread_create,
    dpif_hw_acc_flow_dump_thread_destroy,
    dpif_hw_acc_flow_dump_next,
    dpif_hw_acc_operate,
    dpif_hw_acc_recv_set,
    dpif_hw_acc_handlers_set,
    NULL,                       /* poll_thread_set */
    dpif_hw_acc_queue_to_priority,
    dpif_hw_acc_recv,
    dpif_hw_acc_recv_wait,
    dpif_hw_acc_recv_purge,
    NULL,                       /* register_dp_purge_cb */
    NULL,                       /* register_upcall_cb */
    NULL,                       /* enable_upcall */
    NULL,                       /* disable_upcall */
    NULL,                       /* get_datapath_version */
#ifdef __linux__
    dpif_hw_acc_ct_dump_start,
    dpif_hw_acc_ct_dump_next,
    dpif_hw_acc_ct_dump_done,
    dpif_hw_acc_ct_flush,
#else
    NULL,                       /* ct_dump_start */
    NULL,                       /* ct_dump_next */
    NULL,                       /* ct_dump_done */
    NULL,                       /* ct_flush */
#endif
};
