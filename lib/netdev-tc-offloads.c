/*
 * Copyright (c) 2016 Mellanox Technologies, Ltd.
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

#include "netdev-tc-offloads.h"

#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <linux/filter.h>
#include <linux/gen_stats.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/types.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_packet.h>
#include <net/route.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "coverage.h"
#include "dp-packet.h"
#include "dpif-netlink.h"
#include "dpif-netdev.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "hash.h"
#include "openvswitch/hmap.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "netlink-notifier.h"
#include "netlink-socket.h"
#include "netlink.h"
#include "openvswitch/ofpbuf.h"
#include "openflow/openflow.h"
#include "ovs-atomic.h"
#include "packets.h"
#include "poll-loop.h"
#include "rtnetlink.h"
#include "openvswitch/shash.h"
#include "netdev-provider.h"
#include "openvswitch/match.h"
#include "openvswitch/vlog.h"
#include "tc.h"

VLOG_DEFINE_THIS_MODULE(netdev_tc_offloads);

static struct vlog_rate_limit rl_err = VLOG_RATE_LIMIT_INIT(9999, 5);

static struct hmap ufid_to_tc = HMAP_INITIALIZER(&ufid_to_tc);
static struct hmap tc_to_ufid = HMAP_INITIALIZER(&tc_to_ufid);
static struct ovs_mutex ufid_lock = OVS_MUTEX_INITIALIZER;

struct ufid_to_tc_data {
    struct hmap_node node;
    ovs_u128 ufid;
    uint16_t prio;
    uint32_t handle;
    int ifindex;
    struct netdev *netdev;
};

/* Remove ufid from ufid_to_tc and matching entry from tc_to_ufid hashmap. */
static void
del_ufid_tc_mapping(const ovs_u128 *ufid)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_tc_data *data;
    uint16_t prio;
    uint32_t handle;
    int ifindex;
    size_t hash2;

    ovs_mutex_lock(&ufid_lock);
    HMAP_FOR_EACH_WITH_HASH(data, node, hash, &ufid_to_tc) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            break;
        }
    }

    if (!data) {
        ovs_mutex_unlock(&ufid_lock);
        return;
    }

    /* remove from ufid_to_tc map and get info to remove tc_to_ufid map */
    hmap_remove(&ufid_to_tc, &data->node);
    netdev_close(data->netdev);
    prio = data->prio;
    handle = data->handle;
    ifindex = data->ifindex;
    hash2 = hash_int(hash_int(prio, handle), ifindex);
    free(data);

    HMAP_FOR_EACH_WITH_HASH(data, node, hash2, &tc_to_ufid) {
        if (data->prio == prio && data->handle == handle && data->ifindex == ifindex) {
            break;
        }
    }
    if (data) {
        hmap_remove(&tc_to_ufid, &data->node);
        netdev_close(data->netdev);
        free(data);
    }
    ovs_mutex_unlock(&ufid_lock);
}

/* Add ufid to ufid_tc hashmap and prio/handle/ifindex to tc_ufid hashmap.
 * If those exists already they will be replaced. */
static void
add_ufid_tc_mapping(const ovs_u128 *ufid, int prio, int handle,
                    struct netdev *netdev, int ifindex)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    size_t hash2 = hash_int(hash_int(prio, handle), ifindex);
    struct ufid_to_tc_data *new_data = xzalloc(sizeof *new_data);
    struct ufid_to_tc_data *new_data2 = xzalloc(sizeof *new_data2);

    del_ufid_tc_mapping(ufid);

    new_data->ufid = *ufid;
    new_data->prio = prio;
    new_data->handle = handle;
    new_data->netdev = netdev_ref(netdev);
    new_data->ifindex = ifindex;

    new_data2->ufid = *ufid;
    new_data2->prio = prio;
    new_data2->handle = handle;
    new_data2->netdev = netdev_ref(netdev);
    new_data2->ifindex = ifindex;

    ovs_mutex_lock(&ufid_lock);
    hmap_insert(&ufid_to_tc, &new_data->node, hash);
    hmap_insert(&tc_to_ufid, &new_data2->node, hash2);
    ovs_mutex_unlock(&ufid_lock);
}

/* Get ufid from ufid_tc hashmap.
 *
 * Returns handle if successful and fill prio and netdev for that ufid.
 * Otherwise returns 0.
 */
static int
get_ufid_tc_mapping(const ovs_u128 *ufid, int *prio, struct netdev **netdev)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_tc_data *data;
    int handle = 0;

    ovs_mutex_lock(&ufid_lock);
    HMAP_FOR_EACH_WITH_HASH(data, node, hash, &ufid_to_tc) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            if (prio) {
                *prio = data->prio;
            }
            if (netdev) {
                *netdev = netdev_ref(data->netdev);
            }
            handle = data->handle;
            break;
        }
    }
    ovs_mutex_unlock(&ufid_lock);

    return handle;
}

/* Find ufid in tc_to_ufid hashmap using prio, handle and netdev.
 * The result is saved in ufid.
 *
 * Returns true on success.
 */
static bool
find_ufid(int prio, int handle, struct netdev *netdev, ovs_u128 *ufid)
{
    int ifindex = netdev_get_ifindex(netdev);
    struct ufid_to_tc_data *data;
    size_t hash2 = hash_int(hash_int(prio, handle), ifindex);

    ovs_mutex_lock(&ufid_lock);
    HMAP_FOR_EACH_WITH_HASH(data, node, hash2,  &tc_to_ufid) {
        if (data->prio == prio && data->handle == handle
            && data->ifindex == ifindex) {
            *ufid = data->ufid;
            break;
        }
    }
    ovs_mutex_unlock(&ufid_lock);

    return (data != NULL);
}

int
netdev_tc_flow_flush(struct netdev *netdev)
{
    int ifindex = netdev_get_ifindex(netdev);

    if (ifindex < 0) {
        VLOG_ERR_RL(&rl_err, "failed to get ifindex for %s: %s",
                    netdev_get_name(netdev), ovs_strerror(-ifindex));
        return -ifindex;
    }

    return tc_flush(ifindex);
}

int
netdev_tc_flow_dump_create(struct netdev *netdev,
                           struct netdev_flow_dump **dump_out)
{
    struct netdev_flow_dump *dump;
    int ifindex;

    ifindex = netdev_get_ifindex(netdev);
    if (ifindex < 0) {
        VLOG_ERR_RL(&rl_err, "failed to get ifindex for %s: %s",
                    netdev_get_name(netdev), ovs_strerror(-ifindex));
        return -ifindex;
    }

    dump = xzalloc(sizeof *dump);
    dump->nl_dump = xzalloc(sizeof *dump->nl_dump);
    dump->netdev = netdev_ref(netdev);
    tc_dump_flower_start(ifindex, dump->nl_dump);

    *dump_out = dump;

    return 0;
}

int
netdev_tc_flow_dump_destroy(struct netdev_flow_dump *dump)
{
    nl_dump_done(dump->nl_dump);
    netdev_close(dump->netdev);
    free(dump->nl_dump);
    free(dump);
    return 0;
}

static int
parse_tc_flower_to_match(struct tc_flower *flower,
                         struct match *match,
                         struct nlattr **actions,
                         struct dpif_flow_stats *stats,
                         struct ofpbuf *buf) {
    size_t act_off;
    struct tc_flower_key *key = &flower->key;
    struct tc_flower_key *mask = &flower->mask;
    odp_port_t outport = 0;

    if (flower->ifindex_out) {
        outport = netdev_hmap_port_get_byifidx(flower->ifindex_out);
        if (!outport) {
            return ENOENT;
        }
    }

    ofpbuf_clear(buf);

    match_init_catchall(match);
    match_set_dl_type(match, key->eth_type);
    match_set_dl_src_masked(match, key->src_mac, mask->src_mac);
    match_set_dl_dst_masked(match, key->dst_mac, mask->dst_mac);
    if (key->vlan_id || key->vlan_prio) {
        match_set_dl_vlan(match, htons(key->vlan_id));
        match_set_dl_vlan_pcp(match, key->vlan_prio);
        match_set_dl_type(match, key->encap_eth_type);
    }

    if (key->ip_proto &&
        (key->eth_type == htons(ETH_P_IP)
         || key->eth_type == htons(ETH_P_IPV6))) {
        match_set_nw_proto(match, key->ip_proto);
    }

    match_set_nw_src_masked(match, key->ipv4.ipv4_src, mask->ipv4.ipv4_src);
    match_set_nw_dst_masked(match, key->ipv4.ipv4_dst, mask->ipv4.ipv4_dst);

    match_set_ipv6_src_masked(match,
                              &key->ipv6.ipv6_src, &mask->ipv6.ipv6_src);
    match_set_ipv6_dst_masked(match,
                              &key->ipv6.ipv6_dst, &mask->ipv6.ipv6_dst);

    match_set_tp_dst_masked(match, key->dst_port, mask->dst_port);
    match_set_tp_src_masked(match, key->src_port, mask->src_port);

    if (flower->tunnel.tunnel) {
        match_set_tun_id(match, flower->tunnel.id);
        if (flower->tunnel.ipv4.ipv4_dst) {
            match_set_tun_src(match, flower->tunnel.ipv4.ipv4_src);
            match_set_tun_dst(match, flower->tunnel.ipv4.ipv4_dst);
        } else if (!is_all_zeros(&flower->tunnel.ipv6.ipv6_dst,
                   sizeof flower->tunnel.ipv6.ipv6_dst)) {
            match_set_tun_ipv6_src(match, &flower->tunnel.ipv6.ipv6_src);
            match_set_tun_ipv6_dst(match, &flower->tunnel.ipv6.ipv6_dst);
        }
        match_set_tp_dst(match, flower->tunnel.tp_dst);
    }

    act_off = nl_msg_start_nested(buf, OVS_FLOW_ATTR_ACTIONS);
    {
        if (flower->vlan_pop) {
            nl_msg_put_flag(buf, OVS_ACTION_ATTR_POP_VLAN);
        }

        if (flower->vlan_push_id || flower->vlan_push_prio) {
            struct ovs_action_push_vlan *push;
            push = nl_msg_put_unspec_zero(buf, OVS_ACTION_ATTR_PUSH_VLAN,
                                          sizeof *push);

            push->vlan_tpid = htons(ETH_TYPE_VLAN);
            push->vlan_tci = htons(flower->vlan_push_id
                                   | (flower->vlan_push_prio << 13)
                                   | VLAN_CFI);
        }

        if (flower->set.set) {
            size_t set_offset = nl_msg_start_nested(buf, OVS_ACTION_ATTR_SET);
            size_t tunnel_offset =
                nl_msg_start_nested(buf, OVS_KEY_ATTR_TUNNEL);

            nl_msg_put_be64(buf, OVS_TUNNEL_KEY_ATTR_ID, flower->set.id);
            if (flower->set.ipv4.ipv4_src) {
                nl_msg_put_be32(buf, OVS_TUNNEL_KEY_ATTR_IPV4_SRC,
                                flower->set.ipv4.ipv4_src);
            }
            if (flower->set.ipv4.ipv4_dst) {
                nl_msg_put_be32(buf, OVS_TUNNEL_KEY_ATTR_IPV4_DST,
                                flower->set.ipv4.ipv4_dst);
            }
            if (!is_all_zeros(&flower->set.ipv6.ipv6_src,
                              sizeof flower->set.ipv6.ipv6_src)) {
                nl_msg_put_in6_addr(buf, OVS_TUNNEL_KEY_ATTR_IPV6_SRC,
                                    &flower->set.ipv6.ipv6_src);
            }
            if (!is_all_zeros(&flower->set.ipv6.ipv6_dst,
                              sizeof flower->set.ipv6.ipv6_dst)) {
                nl_msg_put_in6_addr(buf, OVS_TUNNEL_KEY_ATTR_IPV6_DST,
                                    &flower->set.ipv6.ipv6_dst);
            }
            nl_msg_put_be16(buf, OVS_TUNNEL_KEY_ATTR_TP_DST,
                            flower->set.tp_dst);

            nl_msg_end_nested(buf, tunnel_offset);
            nl_msg_end_nested(buf, set_offset);
        }

        if (flower->ifindex_out > 0) {
            nl_msg_put_u32(buf, OVS_ACTION_ATTR_OUTPUT, odp_to_u32(outport));
        }

    }
    nl_msg_end_nested(buf, act_off);

    *actions = ofpbuf_at_assert(buf, act_off, sizeof(struct nlattr));

    if (stats) {
        memset(stats, 0, sizeof *stats);
        stats->n_packets = get_32aligned_u64(&flower->stats.n_packets);
        stats->n_bytes = get_32aligned_u64(&flower->stats.n_bytes);
        stats->used = flower->lastused;
    }

    return 0;
}

bool
netdev_tc_flow_dump_next(struct netdev_flow_dump *dump,
                         struct match *match,
                         struct nlattr **actions,
                         struct dpif_flow_stats *stats,
                         ovs_u128 *ufid,
                         struct ofpbuf *rbuffer,
                         struct ofpbuf *wbuffer)
{
    struct ofpbuf nl_flow;

    while (nl_dump_next(dump->nl_dump, &nl_flow, rbuffer)) {
        struct tc_flower flower;
        struct netdev *netdev = dump->netdev;

        if (parse_netlink_to_tc_flower(&nl_flow, &flower)) {
            continue;
        }

        if (parse_tc_flower_to_match(&flower, match, actions, stats,
                                     wbuffer)) {
            continue;
        }

        if (flower.act_cookie.len) {
            *ufid = *((ovs_u128 *) flower.act_cookie.data);
        } else if (!find_ufid(flower.prio, flower.handle, netdev, ufid)) {
            continue;
        }

        match->wc.masks.in_port.odp_port = u32_to_odp(UINT32_MAX);
        match->flow.in_port.odp_port = dump->port;

        return true;
    }

    return false;
}

int
netdev_tc_flow_put(struct netdev *netdev OVS_UNUSED,
                   struct match *match OVS_UNUSED,
                   struct nlattr *actions OVS_UNUSED,
                   size_t actions_len OVS_UNUSED,
                   struct dpif_flow_stats *stats OVS_UNUSED,
                   const ovs_u128 *ufid OVS_UNUSED,
                   struct offload_info *info OVS_UNUSED)
{
    return EOPNOTSUPP;
}

int
netdev_tc_flow_get(struct netdev *netdev OVS_UNUSED,
                   struct match *match OVS_UNUSED,
                   struct nlattr **actions OVS_UNUSED,
                   struct dpif_flow_stats *stats OVS_UNUSED,
                   const ovs_u128 *ufid OVS_UNUSED,
                   struct ofpbuf *buf OVS_UNUSED)
{
    return EOPNOTSUPP;
}

int
netdev_tc_flow_del(struct netdev *netdev OVS_UNUSED,
                   const ovs_u128 *ufid OVS_UNUSED,
                   struct dpif_flow_stats *stats OVS_UNUSED)
{
    return EOPNOTSUPP;
}

int
netdev_tc_init_flow_api(struct netdev *netdev OVS_UNUSED)
{
    return 0;
}

