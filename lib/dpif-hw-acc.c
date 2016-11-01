
#include <config.h>

#include "dpif-netlink.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <linux/types.h>
#include <linux/pkt_sched.h>
#include <linux/if_ether.h>
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
#include "netdev-provider.h"
#include "dpif-hw-acc.h"
#include "tc.h"
#include "hw-offload-policy.h"

VLOG_DEFINE_THIS_MODULE(dpif_hw_acc);

extern bool SKIP_HW;

static inline void *
nla_data(const struct nlattr *nla)
{
    return (char *) nla + NLA_HDRLEN;
}

static char *
attrname(int type)
{
    static char unkowntype[64];

    switch (type) {
    case OVS_KEY_ATTR_ENCAP:
        return "OVS_KEY_ATTR_ENCAP";
    case OVS_KEY_ATTR_PRIORITY:
        return "OVS_KEY_ATTR_PRIORITY";
    case OVS_KEY_ATTR_CT_LABELS:
        return "OVS_KEY_ATTR_CT_LABELS";
    case OVS_KEY_ATTR_IN_PORT:
        return "OVS_KEY_ATTR_IN_PORT";
    case OVS_KEY_ATTR_ETHERNET:
        return "OVS_KEY_ATTR_ETHERNET";
    case OVS_KEY_ATTR_VLAN:
        return "OVS_KEY_ATTR_VLAN";
    case OVS_KEY_ATTR_ETHERTYPE:
        return "OVS_KEY_ATTR_ETHERTYPE";
    case OVS_KEY_ATTR_IPV4:
        return "OVS_KEY_ATTR_IPV4";
    case OVS_KEY_ATTR_IPV6:
        return "OVS_KEY_ATTR_IPV6";
    case OVS_KEY_ATTR_TCP:
        return "OVS_KEY_ATTR_TCP";
    case OVS_KEY_ATTR_UDP:
        return "OVS_KEY_ATTR_UDP";
    case OVS_KEY_ATTR_ICMP:
        return "OVS_KEY_ATTR_ICMP";
    case OVS_KEY_ATTR_ICMPV6:
        return "OVS_KEY_ATTR_ICMPV6";
    case OVS_KEY_ATTR_ARP:
        return "OVS_KEY_ATTR_ARP";
    case OVS_KEY_ATTR_ND:
        return "OVS_KEY_ATTR_ND";
    case OVS_KEY_ATTR_SKB_MARK:
        return "OVS_KEY_ATTR_SKB_MARK";
    case OVS_KEY_ATTR_TUNNEL:
        return "OVS_KEY_ATTR_TUNNEL";
    case OVS_KEY_ATTR_SCTP:
        return "OVS_KEY_ATTR_SCTP";
    case OVS_KEY_ATTR_TCP_FLAGS:
        return "OVS_KEY_ATTR_TCP_FLAGS";
    case OVS_KEY_ATTR_DP_HASH:
        return "OVS_KEY_ATTR_DP_HASH";
    case OVS_KEY_ATTR_RECIRC_ID:
        return "OVS_KEY_ATTR_RECIRC_ID";
    case OVS_KEY_ATTR_MPLS:
        return "OVS_KEY_ATTR_MPLS";
    case OVS_KEY_ATTR_CT_STATE:
        return "OVS_KEY_ATTR_CT_STATE";
    case OVS_KEY_ATTR_CT_ZONE:
        return "OVS_KEY_ATTR_CT_ZONE";
    case OVS_KEY_ATTR_CT_MARK:
        return "OVS_KEY_ATTR_CT_MARK";
    default:
        sprintf(unkowntype, "unkown_type(%d)\n", type);
        return unkowntype;
    }
}

static char *
printufid(const ovs_u128 * ovs_ufid)
{
    static char ufid[64];

    if (ovs_ufid)
        sprintf(ufid, "%x%x%x%x", ovs_ufid->u32[0], ovs_ufid->u32[1],
                ovs_ufid->u32[2], ovs_ufid->u32[3]);
    else
        sprintf(ufid, "(missing_ufid)");
    return ufid;
}

static inline size_t
hash_ufid(const ovs_u128 * ovs_ufid)
{
    return hash_words64((const uint64_t *) ovs_ufid,
                        sizeof *ovs_ufid / sizeof (uint64_t), 0);
}

static inline size_t
hash_port(odp_port_t port)
{
    return hash_int((int) port, 0);
}

static inline size_t
hash_handle_prio_port(int handle, uint16_t prio, odp_port_t port)
{
    /* TODO: fix utint cast */
    return hash_int((uint32_t) prio, hash_int(handle, hash_port(port)));
}

static struct netdev *
port_find(struct dpif_hw_acc *dpif, odp_port_t port)
{
    struct port_netdev_hash_data *data;
    size_t hash = hash_port(port);
    struct netdev *res = 0;

    ovs_mutex_lock(&dpif->hash_mutex);
    HMAP_FOR_EACH_WITH_HASH(data, node, hash, &dpif->port_to_netdev) {
        if (data->port == port)
            break;
    }
    if (data) {
        res = data->netdev;
        VLOG_DBG
            ("found port mapping: port number %d -> port name %s (pointer: %p)\n",
             port, res->name, res);
    }
    ovs_mutex_unlock(&dpif->hash_mutex);

    return res;
}

static int
port_del_name(struct dpif_hw_acc *dpif, char *name)
{
    struct port_netdev_hash_data *data;

    ovs_mutex_lock(&dpif->hash_mutex);
    HMAP_FOR_EACH(data, node, &dpif->port_to_netdev) {
        if (!strcmp(data->netdev->name, name))
            break;
    }
    if (data)
        hmap_remove(&dpif->port_to_netdev, &data->node);
    ovs_mutex_unlock(&dpif->hash_mutex);

    free(data);
    return data ? 1 : 0;
}

static int
port_del(struct dpif_hw_acc *dpif, odp_port_t port)
{
    struct port_netdev_hash_data *data;
    size_t hash = hash_port(port);

    ovs_mutex_lock(&dpif->hash_mutex);
    HMAP_FOR_EACH_WITH_HASH(data, node, hash, &dpif->port_to_netdev) {
        if (data->port == port)
            break;
    }
    if (data)
        hmap_remove(&dpif->port_to_netdev, &data->node);
    ovs_mutex_unlock(&dpif->hash_mutex);

    free(data);
    return data ? 1 : 0;
}

static int
port_add(struct dpif_hw_acc *dpif, odp_port_t port, struct netdev *netdev)
{
    struct port_netdev_hash_data *data;
    size_t hash = hash_port(port);
    int ret = 0;

    if (!netdev || !netdev->name || !port)
        return -1;

    if (netdev->netdev_class == &netdev_internal_class) {
        if (!strcmp(netdev->name, "skip_hw")) {
            tc_set_skip_hw(true);
        }
        return -1;
    }
    if (port_del(dpif, port) || port_del_name(dpif, netdev->name)) {
        VLOG_DBG
            ("%s %d %s (%p)  port number %d name: %s, deleted to be replaced\n",
             __FILE__, __LINE__, __func__, dpif, port, netdev->name);
        ret = 1;
    }

    data = malloc(sizeof (struct port_netdev_hash_data));
    data->netdev = netdev;
    data->port = port;

    VLOG_DBG
        ("%s %d %s (%p): adding new port mapping: %d -> netdev %p name: %s, type: %s, ifindex: %d, hash: %lu\n",
         __FILE__, __LINE__, __func__, dpif, port, netdev, netdev->name,
         netdev->netdev_class->type, netdev_get_ifindex(netdev), hash);
    ovs_mutex_lock(&dpif->hash_mutex);
    hmap_insert(&dpif->port_to_netdev, &data->node, hash);
    ovs_mutex_unlock(&dpif->hash_mutex);
    return ret;
}

static int
delhandle(struct dpif_hw_acc *dpif, const ovs_u128 * ovs_ufid)
{
    struct ufid_handle_hash_data *data;
    size_t hash;

    if (!ovs_ufid) {
        VLOG_ERR("%s %d %s (%p) can't delete missing ufid\n", __FILE__,
                 __LINE__, __func__, dpif);
        return 0;
    }
    hash = hash_ufid(ovs_ufid);

    VLOG_DBG("%s %d %s (%p): removing %s\n", __FILE__, __LINE__, __func__,
             dpif, printufid(ovs_ufid));

    ovs_mutex_lock(&dpif->hash_mutex);
    HMAP_FOR_EACH_WITH_HASH(data, node_ufid, hash, &dpif->ufid_to_handle) {
        if (!memcmp(&data->ovs_ufid, ovs_ufid, sizeof (*ovs_ufid)))
            break;
    }
    if (data) {
        VLOG_DBG("%s %d %s (%p)  ufid %s found! handle: %d, removing it\n",
                 __FILE__, __LINE__, __func__, dpif, printufid(ovs_ufid),
                 data->handle);
        hmap_remove(&dpif->ufid_to_handle, &data->node_ufid);
        hmap_remove(&dpif->handle_to_ufid, &data->node_handle);
        free(data);
    }
    ovs_mutex_unlock(&dpif->hash_mutex);
    return data ? 1 : 0;
}

static int
puthandle(struct dpif_hw_acc *dpif, const ovs_u128 * ovs_ufid,
          struct netdev *in, odp_port_t port, int handle, uint16_t prio)
{
    int ret = 0;
    size_t hash_to_ufid = hash_handle_prio_port(handle, prio, port);

    if (!ovs_ufid) {
        VLOG_ERR("%s %d %s (%p) missing UFID!\n", __FILE__, __LINE__, __func__,
                 dpif);
        return 0;
    }

    if (delhandle(dpif, ovs_ufid))
        ret = 1;

    struct ufid_handle_hash_data *data =
        malloc(sizeof (struct ufid_handle_hash_data));
    data->ovs_ufid = *ovs_ufid;
    data->handle = handle;
    data->netdev = in;
    data->port = port;
    data->prio = prio;

    ovs_mutex_lock(&dpif->hash_mutex);
    hmap_insert(&dpif->ufid_to_handle, &data->node_ufid, hash_ufid(ovs_ufid));
    hmap_insert(&dpif->handle_to_ufid, &data->node_handle, hash_to_ufid);
    VLOG_DBG
        ("%s %d %s (%p) added mapping %s <-> (handle: %d, prio: %d, port: %d, indev: %p)\n",
         __FILE__, __LINE__, __func__, dpif, printufid(ovs_ufid), handle,
         prio, port, in);
    ovs_mutex_unlock(&dpif->hash_mutex);
    return ret;
}

static ovs_u128 *
findufid(struct dpif_hw_acc *dpif, odp_port_t port, int handle,
         uint16_t prio)
{
    struct ufid_handle_hash_data *data;
    size_t hash = hash_handle_prio_port(handle, prio, port);

    VLOG_DBG
        ("%s %d %s (%p) finding ufid of (handle: %d,  prio: %d,  port: %d), hash: %lu\n",
         __FILE__, __LINE__, __func__, dpif, handle, prio, port, hash);

    ovs_mutex_lock(&dpif->hash_mutex);
    HMAP_FOR_EACH_WITH_HASH(data, node_handle, hash, &dpif->handle_to_ufid) {
        if (data->handle == handle && data->port == port
            && data->prio == prio)
            break;
    }
    ovs_mutex_unlock(&dpif->hash_mutex);

    return data ? &data->ovs_ufid : 0;
}

static int
gethandle(struct dpif_hw_acc *dpif, const ovs_u128 * ovs_ufid,
          struct netdev **in, uint16_t *prio, const char *func, int print)
{
    struct ufid_handle_hash_data *data;
    int handle = 0;
    size_t hash = 0;

    if (in)
        *in = 0;

    if (!ovs_ufid) {
        VLOG_DBG("%s %d %s (%p) called by %s without a ufid.\n", __FILE__,
                 __LINE__, __func__, dpif, func);
        return 0;
    } else
        hash = hash_ufid(ovs_ufid);

    if (print)
        VLOG_DBG("%s %d %s (%p) called by %s to find ufid %s\n", __FILE__,
                 __LINE__, __func__, dpif, func, printufid(ovs_ufid));

    ovs_mutex_lock(&dpif->hash_mutex);
    HMAP_FOR_EACH_WITH_HASH(data, node_ufid, hash, &dpif->ufid_to_handle) {
        if (!memcmp(&data->ovs_ufid, ovs_ufid, sizeof (*ovs_ufid)))
            break;
    }
    ovs_mutex_unlock(&dpif->hash_mutex);

    if (data && (!data->handle || !data->netdev || !data->prio)) {
        VLOG_ERR
            ("mising handle/dev/prio for ufid: %s, handle: %d, netdev: %p, prio: %d\n",
             printufid(ovs_ufid), data->handle, data->netdev, data->prio);
        return 0;
    }
    handle = data ? data->handle : 0;
    if (in)
        *in = data ? data->netdev : 0;
    if (prio)
        *prio = data ? data->prio : 0;
    if (print && handle)
        VLOG_DBG("found ufid: %s, handle: %d, prio: %d, netdev: %p\n",
                 printufid(ovs_ufid), handle, data->prio, data->netdev);
    return handle;
}

static int
get_ovs_port(struct dpif_hw_acc *dpif, int ifindex)
{
    struct port_netdev_hash_data *data;

    HMAP_FOR_EACH(data, node, &dpif->port_to_netdev) {
        if (netdev_get_ifindex(data->netdev) == ifindex) {
            return data->port;
        }
    }
    return -1;
}

static int
dpif_hw_tc_flow_to_dpif_flow(struct dpif_hw_acc *dpif,
                             struct tc_flow *tc_flow,
                             struct dpif_flow *dpif_flow, odp_port_t inport,
                             struct ofpbuf *outflow, struct netdev *indev)
{
    struct ofpbuf mask_d, *mask = &mask_d;

    ofpbuf_init(mask, 512);

    dpif_flow->pmd_id = PMD_ID_NULL;

    size_t key_offset = nl_msg_start_nested(outflow, OVS_FLOW_ATTR_KEY);
    size_t mask_offset = nl_msg_start_nested(mask, OVS_FLOW_ATTR_MASK);

    nl_msg_put_u32(outflow, OVS_KEY_ATTR_IN_PORT, inport);
    nl_msg_put_u32(mask, OVS_KEY_ATTR_IN_PORT, 0xFFFFFFFF);

    /* OVS_KEY_ATTR_ETHERNET */
    struct ovs_key_ethernet *eth_key =
        nl_msg_put_unspec_uninit(outflow, OVS_KEY_ATTR_ETHERNET,
                                 sizeof (*eth_key));
    struct ovs_key_ethernet *eth_key_mask =
        nl_msg_put_unspec_uninit(mask, OVS_KEY_ATTR_ETHERNET,
                                 sizeof (*eth_key_mask));

    memset(eth_key_mask, 0xFF, sizeof (*eth_key_mask));
    eth_key->eth_src = tc_flow->src_mac;
    eth_key->eth_dst = tc_flow->dst_mac;
    eth_key_mask->eth_src = tc_flow->src_mac_mask;
    eth_key_mask->eth_dst = tc_flow->dst_mac_mask;

    nl_msg_put_be16(outflow, OVS_KEY_ATTR_ETHERTYPE, tc_flow->eth_type);
    nl_msg_put_be16(mask, OVS_KEY_ATTR_ETHERTYPE, 0xFFFF);

    /* OVS_KEY_ATTR_IPV6 */
    if (tc_flow->eth_type == ntohs(ETH_P_IPV6)) {
        struct ovs_key_ipv6 *ipv6 =
            nl_msg_put_unspec_uninit(outflow, OVS_KEY_ATTR_IPV6,
                                     sizeof (*ipv6));
        struct ovs_key_ipv6 *ipv6_mask =
            nl_msg_put_unspec_zero(mask, OVS_KEY_ATTR_IPV6,
                                   sizeof (*ipv6_mask));

        memset(&ipv6_mask->ipv6_proto, 0xFF, sizeof (ipv6_mask->ipv6_proto));
        if (tc_flow->ip_proto) ipv6->ipv6_proto = tc_flow->ip_proto;
	else ipv6_mask->ipv6_proto = 0;
        ipv6_mask->ipv6_frag = 0;

	memcpy(ipv6->ipv6_src, tc_flow->ipv6.ipv6_src, sizeof(tc_flow->ipv6.ipv6_src));
	memcpy(ipv6_mask->ipv6_src, tc_flow->ipv6.ipv6_src_mask, sizeof(tc_flow->ipv6.ipv6_src_mask));
	memcpy(ipv6->ipv6_dst, tc_flow->ipv6.ipv6_dst, sizeof(tc_flow->ipv6.ipv6_dst));
	memcpy(ipv6_mask->ipv6_dst, tc_flow->ipv6.ipv6_dst_mask, sizeof(tc_flow->ipv6.ipv6_dst_mask));
    }
    /* OVS_KEY_ATTR_IPV4 */
    if (tc_flow->eth_type == ntohs(ETH_P_IP)) {
        struct ovs_key_ipv4 *ipv4 =
            nl_msg_put_unspec_uninit(outflow, OVS_KEY_ATTR_IPV4,
                                     sizeof (*ipv4));
        struct ovs_key_ipv4 *ipv4_mask =
            nl_msg_put_unspec_zero(mask, OVS_KEY_ATTR_IPV4,
                                   sizeof (*ipv4_mask));

        memset(&ipv4_mask->ipv4_proto, 0xFF, sizeof (ipv4_mask->ipv4_proto));
        if (tc_flow->ip_proto) ipv4->ipv4_proto = tc_flow->ip_proto;
	else ipv4_mask->ipv4_proto = 0;
        ipv4_mask->ipv4_frag = 0;

	if (tc_flow->ipv4.ipv4_src)
		ipv4->ipv4_src = tc_flow->ipv4.ipv4_src;
	if (tc_flow->ipv4.ipv4_src_mask)
		ipv4_mask->ipv4_src = tc_flow->ipv4.ipv4_src_mask;
	if (tc_flow->ipv4.ipv4_dst)
		ipv4->ipv4_dst = tc_flow->ipv4.ipv4_dst;
	if (tc_flow->ipv4.ipv4_dst_mask)
		ipv4_mask->ipv4_dst = tc_flow->ipv4.ipv4_dst_mask;
    }
    if (tc_flow->ip_proto == IPPROTO_ICMPV6) {
	    /* putting a masked out icmp */
	    struct ovs_key_icmpv6 *icmp =
		    nl_msg_put_unspec_uninit(outflow, OVS_KEY_ATTR_ICMPV6,
				    sizeof (*icmp));
	    struct ovs_key_icmpv6 *icmp_mask =
		    nl_msg_put_unspec_uninit(mask, OVS_KEY_ATTR_ICMPV6,
				    sizeof (*icmp_mask));

	    icmp->icmpv6_type = 0;
	    icmp->icmpv6_code = 0;
	    memset(icmp_mask, 0, sizeof (*icmp_mask));
    }
    if (tc_flow->ip_proto == IPPROTO_ICMP) {
	    /* putting a masked out icmp */
	    struct ovs_key_icmp *icmp =
		    nl_msg_put_unspec_uninit(outflow, OVS_KEY_ATTR_ICMP,
				    sizeof (*icmp));
	    struct ovs_key_icmp *icmp_mask =
		    nl_msg_put_unspec_uninit(mask, OVS_KEY_ATTR_ICMP,
				    sizeof (*icmp_mask));

	    icmp->icmp_type = 0;
	    icmp->icmp_code = 0;
	    memset(icmp_mask, 0, sizeof (*icmp_mask));
    }
    if (tc_flow->ip_proto == IPPROTO_TCP) {
	    struct ovs_key_tcp *tcp =
		    nl_msg_put_unspec_uninit(outflow, OVS_KEY_ATTR_TCP,
				    sizeof (*tcp));
	    struct ovs_key_tcp *tcp_mask =
		    nl_msg_put_unspec_uninit(mask, OVS_KEY_ATTR_TCP,
				    sizeof (*tcp_mask));

	    memset(tcp_mask, 0x00, sizeof (*tcp_mask));

	    tcp->tcp_src = tc_flow->src_port;
	    tcp_mask->tcp_src = tc_flow->src_port_mask;
	    tcp->tcp_dst = tc_flow->dst_port;
	    tcp_mask->tcp_dst = tc_flow->dst_port_mask;
    }
    if (tc_flow->ip_proto == IPPROTO_UDP) {
	    struct ovs_key_udp *udp =
		    nl_msg_put_unspec_uninit(outflow, OVS_KEY_ATTR_UDP,
				    sizeof (*udp));
	    struct ovs_key_udp *udp_mask =
		    nl_msg_put_unspec_uninit(mask, OVS_KEY_ATTR_UDP,
				    sizeof (*udp_mask));

	    memset(udp_mask, 0xFF, sizeof (*udp_mask));

	    udp->udp_src = tc_flow->src_port;
	    udp_mask->udp_src = tc_flow->src_port_mask;
	    udp->udp_dst = tc_flow->dst_port;
	    udp_mask->udp_dst = tc_flow->dst_port_mask;
    }
    nl_msg_end_nested(outflow, key_offset);
    nl_msg_end_nested(mask, mask_offset);

    size_t actions_offset =
        nl_msg_start_nested(outflow, OVS_FLOW_ATTR_ACTIONS);
    if (tc_flow->ifindex_out) {
        /* TODO:  make this faster */
        int ovsport = get_ovs_port(dpif, tc_flow->ifindex_out);

        nl_msg_put_u32(outflow, OVS_ACTION_ATTR_OUTPUT, ovsport);
    }
    nl_msg_end_nested(outflow, actions_offset);

    struct nlattr *mask_attr =
        ofpbuf_at_assert(mask, mask_offset, sizeof *mask_attr);
    void *mask_data = ofpbuf_put_uninit(outflow, mask_attr->nla_len);

    memcpy(mask_data, mask_attr, mask_attr->nla_len);
    mask_attr = mask_data;

    struct nlattr *key_attr =
        ofpbuf_at_assert(outflow, key_offset, sizeof *key_attr);
    struct nlattr *actions_attr =
        ofpbuf_at_assert(outflow, actions_offset, sizeof *actions_attr);

    dpif_flow->key = nl_attr_get(key_attr);
    dpif_flow->key_len = nl_attr_get_size(key_attr);
    dpif_flow->mask = nl_attr_get(mask_attr);
    dpif_flow->mask_len = nl_attr_get_size(mask_attr);
    dpif_flow->actions = nl_attr_get(actions_attr);
    dpif_flow->actions_len = nl_attr_get_size(actions_attr);

    if (tc_flow->stats.n_packets.hi || tc_flow->stats.n_packets.lo) {
        dpif_flow->stats.used = tc_flow->lastused ? tc_flow->lastused : 0;
        dpif_flow->stats.n_packets =
            get_32aligned_u64(&tc_flow->stats.n_packets);
        dpif_flow->stats.n_bytes = get_32aligned_u64(&tc_flow->stats.n_bytes);
    } else {
        dpif_flow->stats.used = 0;
        dpif_flow->stats.n_packets = 0;
        dpif_flow->stats.n_bytes = 0;
    }
    dpif_flow->stats.tcp_flags = 0;

    dpif_flow->ufid_present = false;

    ovs_u128 *ovs_ufid =
        findufid(dpif, inport, tc_flow->handle, tc_flow->prio);
    if (ovs_ufid) {
        VLOG_DBG("Found UFID!, handle: %d, ufid: %s\n", tc_flow->handle,
                 printufid(ovs_ufid));
        dpif_flow->ufid = *ovs_ufid;
        dpif_flow->ufid_present = true;
    } else {
        VLOG_DBG("Creating new UFID\n");
        ovs_assert(dpif_flow->key && dpif_flow->key_len);
        dpif_flow_hash(&dpif->dpif, dpif_flow->key, dpif_flow->key_len,
                       &dpif_flow->ufid);
        dpif_flow->ufid_present = true;
        puthandle(dpif, &dpif_flow->ufid, indev, inport, tc_flow->handle,
                  tc_flow->prio);
    }

    return 0;
}

static struct dpif_hw_acc *
dpif_hw_acc_cast(const struct dpif *dpif)
{
    dpif_assert_class(dpif, &dpif_hw_acc_class);
    return CONTAINER_OF(dpif, struct dpif_hw_acc, dpif);
}

static int
initmaps(struct dpif_hw_acc *dpif)
{
    hmap_init(&dpif->port_to_netdev);
    hmap_init(&dpif->ufid_to_handle);
    hmap_init(&dpif->handle_to_ufid);
    hmap_init(&dpif->mask_to_prio);
    ovs_mutex_init(&dpif->hash_mutex);
    return 0;
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

    initmaps(dpif);

    *CONST_CAST(const char **, &dpif->name) = xstrdup(name);
    uint16_t netflow_id = hash_string(dpif->name, 0);

    dpif->lp_dpif_netlink = lp_dpif_netlink;

    dpif_init(&dpif->dpif, &dpif_hw_acc_class, dpif->name, netflow_id >> 8,
              netflow_id);

    *dpifp = &dpif->dpif;

    if (!create) {
        VLOG_DBG
            ("%s %d %s(%p) requesting existing port dump, from dpif-netlink only.\n",
             __FILE__, __LINE__, __func__, dpif);
        DPIF_PORT_FOR_EACH(&dpif_port, &dump, dpif->lp_dpif_netlink) {
            VLOG_DBG("%s %d %s(%p) port: %s, type: %s\n", __FILE__, __LINE__,
                     __func__, dpif, dpif_port.name, dpif_port.type);
            if (dpif_port.type && !strcmp(dpif_port.type, "internal")) {
                if (!strcmp(dpif_port.name, "skip_hw")) {
                    tc_set_skip_hw(true);
                }
                continue;
            }
            if (!netdev_open(dpif_port.name, dpif_port.type, &netdev)) {
                VLOG_DBG
                    ("%s %d %s(%p) opened a new netdev: %s, type: %s, ifindex: %d\n",
                     __FILE__, __LINE__, __func__, dpif, netdev->name,
                     netdev->netdev_class->type, netdev_get_ifindex(netdev));
                port_add(dpif, dpif_port.port_no, netdev);
            }
        }
    }
    VLOG_DBG("%s %d %s(%p) port dump end.\n", __FILE__, __LINE__, __func__,
             dpif);

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
    int error;
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    VLOG_DBG("%s %d %s (%p): request to add  netdev: %s\n", __FILE__, __LINE__,
             __func__, dpif, netdev->name);
    error =
        dpif->lp_dpif_netlink->dpif_class->port_add(dpif->lp_dpif_netlink,
                                                    netdev, port_nop);
    if (!error)
        port_add(dpif, *port_nop, netdev);
    else
        VLOG_ERR("%s %d %s (%p): failed to add port\n", __FILE__, __LINE__,
                 __func__, dpif);

    return error;
}

static int
dpif_hw_acc_port_del(struct dpif *dpif_, odp_port_t port_no)
{
    int error;
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    error =
        dpif->lp_dpif_netlink->dpif_class->port_del(dpif->lp_dpif_netlink,
                                                    port_no);
    if (!error)
        port_del(dpif, port_no);
    return error;
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

static bool
odp_mask_attr_is_wildcard(const struct nlattr *ma)
{
    return is_all_zeros(nl_attr_get(ma), nl_attr_get_size(ma));
}

static bool
odp_mask_is_exact(enum ovs_key_attr attr, const void *mask, size_t size)
{
    if (attr == OVS_KEY_ATTR_TCP_FLAGS) {
        return TCP_FLAGS(*(ovs_be16 *) mask) == TCP_FLAGS(OVS_BE16_MAX);
    }
    if (attr == OVS_KEY_ATTR_IPV6) {
        const struct ovs_key_ipv6 *ipv6_mask = mask;

        return ((ipv6_mask->ipv6_label & htonl(IPV6_LABEL_MASK))
                == htonl(IPV6_LABEL_MASK))
            && ipv6_mask->ipv6_proto == UINT8_MAX
            && ipv6_mask->ipv6_tclass == UINT8_MAX
            && ipv6_mask->ipv6_hlimit == UINT8_MAX
            && ipv6_mask->ipv6_frag == UINT8_MAX
            && ipv6_mask_is_exact((const struct in6_addr *)
                                  ipv6_mask->ipv6_src)
            && ipv6_mask_is_exact((const struct in6_addr *)
                                  ipv6_mask->ipv6_dst);
    }
    if (attr == OVS_KEY_ATTR_TUNNEL) {
        return false;
    }

    if (attr == OVS_KEY_ATTR_ARP) {
        /* ARP key has padding, ignore it. */
        BUILD_ASSERT_DECL(sizeof (struct ovs_key_arp) == 24);
        BUILD_ASSERT_DECL(offsetof(struct ovs_key_arp, arp_tha) == 10 + 6);
        size = offsetof(struct ovs_key_arp, arp_tha) + ETH_ADDR_LEN;

        ovs_assert(((uint16_t *) mask)[size / 2] == 0);
    }

    return is_all_ones(mask, size);
}

static bool
odp_mask_attr_is_exact(const struct nlattr *ma)
{
    enum ovs_key_attr attr = nl_attr_type(ma);
    const void *mask;
    size_t size;

    if (attr == OVS_KEY_ATTR_TUNNEL) {
        return false;
    } else {
        mask = nl_attr_get(ma);
        size = nl_attr_get_size(ma);
    }

    return odp_mask_is_exact(attr, mask, size);
}

static int
parse_to_tc_flow(struct dpif_hw_acc *dpif, struct tc_flow *tc_flow,
                 const struct nlattr *key, int key_len,
                 const struct nlattr *key_mask, int key_mask_len)
{
    size_t left;
    const struct nlattr *a;
    const struct nlattr *mask[__OVS_KEY_ATTR_MAX] = { 0 };

    VLOG_DBG("parsing mask:\n");
    NL_ATTR_FOR_EACH_UNSAFE(a, left, key_mask, key_mask_len) {
        mask[nl_attr_type(a)] = a;
    }

    VLOG_DBG("parsing key attributes:\n");
    NL_ATTR_FOR_EACH_UNSAFE(a, left, key, key_len) {
        const struct nlattr *ma = mask[nl_attr_type(a)];
        bool is_wildcard = false;
        bool is_exact = true;

        if (key_mask && key_mask_len) {
            is_wildcard = ma ? odp_mask_attr_is_wildcard(ma) : true;
            is_exact = ma ? odp_mask_attr_is_exact(ma) : false;
        }

        if (is_exact)
            VLOG_DBG("mask: %s exact: %p\n", attrname(nl_attr_type(a)), ma);
        else if (is_wildcard)
            VLOG_DBG("mask: %s wildcard: %p\n", attrname(nl_attr_type(a)), ma);
        else
            VLOG_DBG("mask %s is partial, ma: %p\n", attrname(nl_attr_type(a)),
                     ma);

        switch (nl_attr_type(a)) {
        case OVS_KEY_ATTR_UNSPEC:
        case OVS_KEY_ATTR_PRIORITY:
        case OVS_KEY_ATTR_SKB_MARK:
        case OVS_KEY_ATTR_CT_STATE:
        case OVS_KEY_ATTR_CT_ZONE:
        case OVS_KEY_ATTR_CT_MARK:
        case OVS_KEY_ATTR_CT_LABELS:
        case OVS_KEY_ATTR_ND:
        case OVS_KEY_ATTR_MPLS:
        case OVS_KEY_ATTR_DP_HASH:
        case OVS_KEY_ATTR_TUNNEL:
        case OVS_KEY_ATTR_SCTP:
        case OVS_KEY_ATTR_ICMP:
        case OVS_KEY_ATTR_ARP:
        case OVS_KEY_ATTR_ICMPV6:;
            if (is_wildcard) {
                VLOG_DBG("unsupported key attribute: %s is wildcard\n",
                         attrname(nl_attr_type(a)));
                break;
            }
            VLOG_ERR("unsupported key attribute: %s is not wildcard\n",
                     attrname(nl_attr_type(a)));
            return 1;
            break;

        case OVS_KEY_ATTR_TCP_FLAGS:
        case OVS_KEY_ATTR_RECIRC_ID:
            /* IGNORE this attributes for now, (might disable some of it in
             * probe? */
            VLOG_DBG
                ("ignoring attribute %s -- fix me, exact: %s, wildcard: %s, partial: %s\n",
                 attrname(nl_attr_type(a)), is_exact ? "yes" : "no",
                 is_wildcard ? "yes" : "no", (!is_wildcard
                                              && !is_exact) ? "yes" : "no");
            break;

        case OVS_KEY_ATTR_VLAN:{
		ovs_be16 tci = nl_attr_get_be16(a);
		ovs_be16 tci_mask = ma ? nl_attr_get_be16(ma) : OVS_BE16_MAX;
		if (vlan_tci_to_vid(tci_mask) != VLAN_VID_MASK) {
			/* Partially masked. */
			VLOG_ERR("unsupported partial mask on vlan_vid attribute");
			return 1;
		}
		VLOG_DBG("vid=%"PRIu16, vlan_tci_to_vid(tci));
		tc_flow->vlan_id = vlan_tci_to_vid(tci);
		if (vlan_tci_to_pcp(tci_mask) != (VLAN_PCP_MASK >> VLAN_PCP_SHIFT)) {
			/* Partially masked. */
			VLOG_ERR("unsupported partial mask on vlan_pcp attribute");
			return 1;
		}
		VLOG_DBG("pcp/prio=%"PRIu16, vlan_tci_to_pcp(tci));
		tc_flow->vlan_prio = vlan_tci_to_pcp(tci);
                if (!(tci & htons(VLAN_CFI))) {
			VLOG_ERR("unsupported partial mask on vlan cfi=0  attribute");
			return 1;
		}
	}
	break;
        case OVS_KEY_ATTR_ENCAP:{
		VLOG_DBG("ENCAP!\n.");
		const struct nlattr *nested_encap = nl_attr_get(a);
		const size_t encap_len = nl_attr_get_size(a);
		const struct nlattr *nested_encap_mask = nl_attr_get(ma);
		const size_t nested_encap_mask_len = nl_attr_get_size(ma);
		struct tc_flow encap_flow;

		int nested_cant_offload = parse_to_tc_flow(dpif, &encap_flow,
                                                           nested_encap, encap_len,
                                                           nested_encap_mask,
                                                           nested_encap_mask_len);
		VLOG_DBG("end of ENCAP!\n.");
		if (nested_cant_offload) return 1;
		tc_flow->encap_ip_proto = encap_flow.ip_proto;
		tc_flow->encap_eth_type = encap_flow.eth_type;
		memcpy(&tc_flow->encap_ipv4, &encap_flow.ipv4,
                      (sizeof(encap_flow.ipv4) > sizeof(encap_flow.ipv6)?
                           sizeof(encap_flow.ipv4) : sizeof(encap_flow.ipv6)));
		VLOG_DBG("encap_eth_type(0x%x)", encap_flow.eth_type);
		VLOG_DBG("encap ip proto (%d)", encap_flow.ip_proto);
	}
	break;

        case OVS_KEY_ATTR_IN_PORT:{
                if (!is_exact) {
                    VLOG_ERR("%s isn't exact, can't offload!\n",
                             attrname(nl_attr_type(a)));
                    return 1;
                }

                VLOG_DBG("in_port(%d)\n", nl_attr_get_u32(a));
                tc_flow->ovs_inport = nl_attr_get_u32(a);
                tc_flow->indev = port_find(dpif, tc_flow->ovs_inport);
                tc_flow->ifindex =
                    tc_flow->indev ? netdev_get_ifindex(tc_flow->indev) : 0;
                if (!tc_flow->ovs_inport || !tc_flow->ifindex) {
                    VLOG_ERR
                        ("RESULT: not found inport: %d or ifindex: %d for ovs in_port: %d\n",
                         tc_flow->ovs_inport, tc_flow->ifindex,
                         tc_flow->ovs_inport);
                    return 1;
                }
            }
            break;

        case OVS_KEY_ATTR_ETHERNET:{
                const struct ovs_key_ethernet *eth_key = 0;
                struct ovs_key_ethernet full_mask;

                memset(&full_mask, 0xFF, sizeof (full_mask));

		/* TODO: fix masks on mac address (because of HW syndrome 0x3ad328) */
                ma = 0;

                const struct ovs_key_ethernet *eth_key_mask =
                    ma ? nla_data(ma) : &full_mask;
                eth_key = nla_data(a);

                const struct eth_addr *src = &eth_key->eth_src;
                const struct eth_addr *src_mask = &eth_key_mask->eth_src;
                const struct eth_addr *dst = &eth_key->eth_dst;
                const struct eth_addr *dst_mask = &eth_key_mask->eth_dst;

                memcpy(&tc_flow->src_mac, src, sizeof (tc_flow->src_mac));
                memcpy(&tc_flow->src_mac_mask, src_mask,
                       sizeof (tc_flow->src_mac_mask));
                memcpy(&tc_flow->dst_mac, dst, sizeof (tc_flow->dst_mac));
                memcpy(&tc_flow->dst_mac_mask, dst_mask,
                       sizeof (tc_flow->dst_mac_mask));

                VLOG_DBG("eth(src=" ETH_ADDR_FMT ", src_mask=" ETH_ADDR_FMT
                         ", dst=" ETH_ADDR_FMT ", dst_mask=" ETH_ADDR_FMT "\n",
                         ETH_ADDR_ARGS(tc_flow->src_mac),
                         ETH_ADDR_ARGS(tc_flow->src_mac_mask),
                         ETH_ADDR_ARGS(tc_flow->dst_mac),
                         ETH_ADDR_ARGS(tc_flow->dst_mac_mask));
            }
            break;
        case OVS_KEY_ATTR_ETHERTYPE:{
                if (!is_exact) {
                    VLOG_ERR("attribute %s isn't exact, can't offload!\n",
                             attrname(nl_attr_type(a)));
                    return 1;
                }

                tc_flow->eth_type = nl_attr_get_be16(a);
                VLOG_DBG("eth_type(0x%04x)\n", ntohs(tc_flow->eth_type));
            }
            break;
	case OVS_KEY_ATTR_IPV6:{
                const struct ovs_key_ipv6 *ipv6 = nla_data(a);
                struct ovs_key_ipv6 full_mask;

                memset(&full_mask, 0xFF, sizeof (full_mask));
                const struct ovs_key_ipv6 *ipv6_mask =
                    ma ? nla_data(ma) : &full_mask;

                if (ipv6_mask->ipv6_frag) {	
                    VLOG_WARN
                        ("*** ignoring exact or partial mask on unsupported ipv6_frag, mask: %x",
                         ipv6_mask->ipv6_frag);
                }
		if (ipv6_mask->ipv6_tclass || ipv6_mask->ipv6_hlimit || ipv6_mask->ipv6_label) {	
                    VLOG_ERR
                        ("ipv6 mask exact or partial one of unsupported sub attributes (tclass: %x, hlimit: %x, label: %x)\n",
                         ipv6_mask->ipv6_tclass, ipv6_mask->ipv6_hlimit,
                         ipv6_mask->ipv6_label);
                    return 1;
		}
                if (ipv6_mask->ipv6_proto != 0
                    && ipv6_mask->ipv6_proto != 0xFF) {
                    VLOG_WARN
                        ("*** ignoring partial mask on ipv6_proto, taking exact ip_proto: %d (%x)\n",
                         ipv6_mask->ipv6_proto, ipv6->ipv6_proto);
                }
                /* If not wildcard out, take exact match for ipv6_proto
                 * (ignoring mask) */
                if (ipv6_mask->ipv6_proto != 0)
                    tc_flow->ip_proto = ipv6->ipv6_proto;

		memcpy(tc_flow->ipv6.ipv6_src, ipv6->ipv6_src, sizeof(ipv6->ipv6_src));
		memcpy(tc_flow->ipv6.ipv6_src_mask, ipv6_mask->ipv6_src, sizeof(ipv6_mask->ipv6_src));

		memcpy(tc_flow->ipv6.ipv6_dst, ipv6->ipv6_dst, sizeof(ipv6->ipv6_dst));
		memcpy(tc_flow->ipv6.ipv6_dst_mask, ipv6_mask->ipv6_dst, sizeof(ipv6_mask->ipv6_dst));
	    }
            break;
        case OVS_KEY_ATTR_IPV4:{
                const struct ovs_key_ipv4 *ipv4 = nla_data(a);
                struct ovs_key_ipv4 full_mask;

                memset(&full_mask, 0xFF, sizeof (full_mask));
                const struct ovs_key_ipv4 *ipv4_mask =
                    ma ? nla_data(ma) : &full_mask;

                if (ipv4_mask->ipv4_frag) {
                    VLOG_WARN
                        ("*** ignoring exact or partial mask on unsupported ipv4_frag, mask: %x",
                         ipv4_mask->ipv4_frag);
                }

                if (ipv4_mask->ipv4_ttl || ipv4_mask->ipv4_tos) {
                    VLOG_ERR
                        ("ipv4 mask exact or partial one of unsupported sub attributes (ttl: %x, tos: %x, frag: %x)\n",
                         ipv4_mask->ipv4_ttl, ipv4_mask->ipv4_tos,
                         ipv4_mask->ipv4_frag);
                    return 1;
                }

                if (ipv4_mask->ipv4_proto != 0
                    && ipv4_mask->ipv4_proto != 0xFF) {
                    VLOG_WARN
                        ("*** ignoring partial mask on ipv4_proto, taking exact ip_proto: %d (%x)\n",
                         ipv4_mask->ipv4_proto, ipv4->ipv4_proto);
                }

                /* If not wildcard out, take exact match for ipv4_proto
                 * (ignoring mask) */
                if (ipv4_mask->ipv4_proto != 0)
                    tc_flow->ip_proto = ipv4->ipv4_proto;

                if (ipv4_mask->ipv4_src) {
                    tc_flow->ipv4.ipv4_src = ipv4->ipv4_src;
                    tc_flow->ipv4.ipv4_src_mask = ipv4_mask->ipv4_src;
                }
                if (ipv4_mask->ipv4_dst) {
                    tc_flow->ipv4.ipv4_dst = ipv4->ipv4_dst;
                    tc_flow->ipv4.ipv4_dst_mask = ipv4_mask->ipv4_dst;
                }
            }
            break;
        case OVS_KEY_ATTR_TCP:{
                struct ovs_key_tcp full_mask;

                memset(&full_mask, 0xFF, sizeof (full_mask));
                const struct ovs_key_tcp *tcp_mask =
                    ma ? nla_data(ma) : &full_mask;
                const struct ovs_key_tcp *tcp = nla_data(a);

                if (tcp_mask->tcp_src) {
                    tc_flow->src_port = tcp->tcp_src;
                    tc_flow->src_port_mask = tcp_mask->tcp_src;
                }
                if (tcp_mask->tcp_dst) {
                    tc_flow->dst_port = tcp->tcp_dst;
                    tc_flow->dst_port_mask = tcp_mask->tcp_dst;
                }

                VLOG_DBG("tcp(src=%d, msk: 0x%x, dst=%d, msk: 0x%x)\n",
                         htons(tcp->tcp_src), htons(tcp_mask->tcp_src),
                         htons(tcp->tcp_dst), htons(tcp_mask->tcp_dst));
            }
            break;
        case OVS_KEY_ATTR_UDP:{
                struct ovs_key_udp full_mask;

                memset(&full_mask, 0xFF, sizeof (full_mask));
                const struct ovs_key_udp *udp_mask =
                    ma ? nla_data(ma) : &full_mask;
                const struct ovs_key_udp *udp = nla_data(a);

                if (udp_mask->udp_src) {
                    tc_flow->src_port = udp->udp_src;
                    tc_flow->src_port_mask = udp_mask->udp_src;
                }
                if (udp_mask->udp_dst) {
                    tc_flow->dst_port = udp->udp_dst;
                    tc_flow->dst_port_mask = udp_mask->udp_dst;
                }
                VLOG_DBG("udp(src=%d/0x%x, dst=%d/0x%x)\n",
                         htons(udp->udp_src), htons(udp_mask->udp_src),
                         htons(udp->udp_dst), htons(udp_mask->udp_dst));
            }
            break;

        case __OVS_KEY_ATTR_MAX:
        default:
            VLOG_ERR("unknown (default/max) key attribute: %s\n",
                     attrname(nl_attr_type(a)));
            return 1;
        }
    }
    VLOG_DBG("--- finished parsing attr - can offload!\n");
    return 0;

}

#define PRIO_ADD_TO_HASH(var) \
do { \
    hash_mask = hash_bytes(&var, sizeof(var), hash_mask); \
    memcpy(&buf[i], &var, sizeof(var)); \
    i+= sizeof(var); \
} while (0)

static uint16_t 
get_new_prio(struct dpif_hw_acc *dpif, struct tc_flow *tc_flow) 
{
   struct mask_prio_data *data;
   size_t hash_mask = 0;
   char buf[128];
   size_t i = 0;
  
   memset(buf, 0, sizeof(buf));

   PRIO_ADD_TO_HASH(tc_flow->dst_mac_mask);
   PRIO_ADD_TO_HASH(tc_flow->src_mac_mask);

   PRIO_ADD_TO_HASH(tc_flow->src_port_mask);
   PRIO_ADD_TO_HASH(tc_flow->dst_port_mask);

   PRIO_ADD_TO_HASH(tc_flow->encap_ipv4.ipv4_src_mask);
   PRIO_ADD_TO_HASH(tc_flow->encap_ipv4.ipv4_dst_mask);

   PRIO_ADD_TO_HASH(tc_flow->encap_ipv6.ipv6_src_mask);
   PRIO_ADD_TO_HASH(tc_flow->encap_ipv6.ipv6_dst_mask);

   PRIO_ADD_TO_HASH(tc_flow->ipv4.ipv4_src_mask);
   PRIO_ADD_TO_HASH(tc_flow->ipv4.ipv4_dst_mask);

   PRIO_ADD_TO_HASH(tc_flow->ipv6.ipv6_src_mask);
   PRIO_ADD_TO_HASH(tc_flow->ipv6.ipv6_dst_mask);

   PRIO_ADD_TO_HASH(tc_flow->eth_type);

   ovs_mutex_lock(&dpif->hash_mutex);
   HMAP_FOR_EACH_WITH_HASH(data, node, hash_mask, &dpif->mask_to_prio) {
       if (data->data && data->len == i &&
               !memcmp(buf, data->data, data->len)) {
                ovs_mutex_unlock(&dpif->hash_mutex);
                return data->prio; 
        }
   }
   
   struct mask_prio_data *data_mask = malloc(sizeof(struct mask_prio_data)); 
   memcpy(data_mask->data, buf, i);
   data_mask->len = i;
   data_mask->prio = ++dpif->last_prio;
   hmap_insert(&dpif->mask_to_prio, &data_mask->node, hash_mask);
   ovs_mutex_unlock(&dpif->hash_mutex);

   return data_mask->prio;
}

static enum dpif_hw_offload_policy
parse_flow_put(struct dpif_hw_acc *dpif, struct dpif_flow_put *put)
{

/*
 * if this is a modify flow cmd and the policy changed: 
 * 	delete the old one
 * handle the new/modify flow
 *
 *
*/
    const struct nlattr *a;
    size_t left;
    struct netdev *in = 0;
    enum dpif_hw_offload_policy policy;

    int probe_feature = ((put->flags & DPIF_FP_PROBE) ? 1 : 0);

    if (probe_feature) {
        VLOG_DBG("\n.\nPROBE REQUEST!\n.\n");
        /* see usage at dpif_probe_feature, we might want to intercept and
         * disable some features */
        return DPIF_HW_NO_OFFLAOAD;
    }
    int cmd =
        put->flags & DPIF_FP_CREATE ? OVS_FLOW_CMD_NEW : OVS_FLOW_CMD_SET;
    if (!put->ufid) {
        VLOG_INFO
            ("%s %d %s missing ufid for flow put, might be from dpctl add-flow.",
             __FILE__, __LINE__, __func__);
    }

    policy = HW_offload_test_put(dpif, put);
    uint16_t getprio = 0;
    int handle = gethandle(dpif, put->ufid, &in, &getprio, "DPIF_OP_FLOW_PUT", 1);

    if (policy == DPIF_HW_NO_OFFLAOAD)
        return DPIF_HW_NO_OFFLAOAD;

    if (cmd == OVS_FLOW_CMD_NEW)
        VLOG_DBG("cmd is OVS_FLOW_CMD_NEW - create\n");
    else
        VLOG_DBG("cmd is OVS_FLOW_CMD_SET - modify\n");

    if (put->flags & DPIF_FP_ZERO_STATS && cmd == OVS_FLOW_CMD_SET)
        VLOG_WARN
            ("We need to zero the stats of a modified flow, not implemented, ignored\n");

    if (put->stats)
        VLOG_WARN("FLOW PUT WANTS STATS\n");

    /* if not present, and cmd == OVS_FLOW_CMD_SET, means don't modify ACTIONs 
     * (which we wrongly parse as a drop rule) see include/odp-netlink.h +:490
     * to clear actions with OVS_FLOW_CMD_SET, actions will be present but
     * empty */
    if (!put->key) {
        VLOG_ERR("%s %d %s error ,missing key, cmd: %d!", __FILE__, __LINE__,
                 __func__, cmd);
        return DPIF_HW_NO_OFFLAOAD;
    }
    if (!put->actions) {
        if (cmd == OVS_FLOW_CMD_SET) {
            VLOG_WARN
                ("%s %d %s missing actions on cmd modify, find and modify key only",
                 __FILE__, __LINE__, __func__);
            return DPIF_HW_NO_OFFLAOAD;
        }
    }

    int outport_count = 0;

    VLOG_DBG("parsing actions\n");
    NL_ATTR_FOR_EACH_UNSAFE(a, left, put->actions, put->actions_len) {
        if (nl_attr_type(a) == OVS_ACTION_ATTR_OUTPUT) {
            VLOG_DBG("output to port: %d\n", nl_attr_get_u32(a));
            outport_count++;
        }
    }
    if (outport_count == 0)
        VLOG_DBG("output to port: drop\n");

    struct ds ds;

    ds_init(&ds);
    ds_clear(&ds);
    if (put->ufid) {
        odp_format_ufid(put->ufid, &ds);
        ds_put_cstr(&ds, ", ");
    }

    ds_put_cstr(&ds, "verbose: ");
    odp_flow_format(put->key, put->key_len, put->mask, put->mask_len, 0, &ds,
                    true);
    ds_put_cstr(&ds, ", not_verbose: ");
    odp_flow_format(put->key, put->key_len, put->mask, put->mask_len, 0, &ds,
                    false);

    /* can also use dpif_flow_stats_format(&f->stats, ds) to print stats */

    ds_put_cstr(&ds, ", actions:");
    format_odp_actions(&ds, put->actions, put->actions_len);
    VLOG_DBG("%s\n", ds_cstr(&ds));
    ds_destroy(&ds);

    /* parse tc_flow */
    struct tc_flow tc_flow;

    memset(&tc_flow, 0, sizeof (tc_flow));
    tc_flow.handle = handle;
    int cant_offload =
        parse_to_tc_flow(dpif, &tc_flow, put->key, put->key_len, put->mask,
                         put->mask_len);

    int new = handle ? 0 : 1;

    VLOG_DBG
        ("cant_offload: %d ifindex: %d, eth_type: %x, ip_proto: %d,  outport_count: %d\n",
         cant_offload, tc_flow.ifindex, ntohs(tc_flow.eth_type),
         tc_flow.ip_proto, outport_count);
    if (!cant_offload && tc_flow.ifindex && tc_flow.eth_type
        && outport_count <= 1) {
        uint16_t prio = get_new_prio(dpif, &tc_flow);

        VLOG_DBG("RESULT: %p, ***** offloading (HW_ONLY!), prio: %d\n", dpif, prio);
        if (cmd != OVS_FLOW_CMD_NEW && !handle) {
            /* modify and flow is now offloadable, remove from kernel netlink
             * datapath */
            int error =
                dpif_flow_del(dpif->lp_dpif_netlink, put->key, put->key_len,
                              put->ufid, PMD_ID_NULL, NULL);

            if (!error)
                VLOG_DBG("modify, deleted old flow and offloading new\n");
            else
                VLOG_ERR("modify, error: %d\n", error);
        }

        int error = 0;

        outport_count = 0;
	/* TODO: actions_len = 0 <=> drop rule */
        NL_ATTR_FOR_EACH_UNSAFE(a, left, put->actions, put->actions_len) {
            if (nl_attr_type(a) == OVS_ACTION_ATTR_OUTPUT) {
                outport_count++;

                tc_flow.ovs_outport = nl_attr_get_u32(a);
                tc_flow.outdev = port_find(dpif, tc_flow.ovs_outport);
                tc_flow.ifindex_out =
                    tc_flow.outdev ? netdev_get_ifindex(tc_flow.outdev) : 0;
                if (tc_flow.ifindex_out) {
                    VLOG_DBG
                        (" **** handle: %d, new? %d, adding %d -> %d (ifindex: %d -> %d)\n",
                         tc_flow.handle, new, tc_flow.ovs_inport,
                         tc_flow.ovs_outport, tc_flow.ifindex,
                         tc_flow.ifindex_out);
        
                    int error = tc_replace_flower(&tc_flow, prio);

                    if (!error) {
                        if (new)
                            puthandle(dpif, put->ufid, tc_flow.indev,
                                      tc_flow.ovs_inport, tc_flow.handle,
                                      tc_flow.prio);

                        VLOG_DBG(" **** offloaded! handle: %d (%x)\n",
                                 tc_flow.handle, tc_flow.handle);
                    } else
                        VLOG_ERR
                            (" **** error! adding fwd rule! tc error: %d\n",
                             error);
                } else {
                    VLOG_ERR
                        (" **** error! not found output port %d, ifindex: %d\n",
                         tc_flow.ovs_outport, tc_flow.ifindex_out);
                    break;
                }
            }
            else if (nl_attr_type(a) == OVS_ACTION_ATTR_PUSH_VLAN) {
		const struct ovs_action_push_vlan *vlan_push = nl_attr_get(a);
		tc_flow.vlan_push_id = vlan_tci_to_vid(vlan_push->vlan_tci);
		tc_flow.vlan_push_prio = vlan_tci_to_pcp(vlan_push->vlan_tci);
	    }
	    else if (nl_attr_type(a) == OVS_ACTION_ATTR_POP_VLAN) {
		tc_flow.vlan_pop = 1;
	    }
	    else {
		VLOG_ERR("Unsupported output type!\n");
		return DPIF_HW_NO_OFFLAOAD;
	    }
        }
        if (!outport_count) {
            VLOG_DBG
                (" ***** handle: %d, new? %d, adding %d -> DROP (ifindex: %d -> DROP)\n",
                 tc_flow.handle, new, tc_flow.ovs_inport, tc_flow.ifindex);
            error = tc_replace_flower(&tc_flow, prio);
            if (!error) {
                if (new)
                    puthandle(dpif, put->ufid, tc_flow.indev,
                              tc_flow.ovs_inport, tc_flow.handle,
                              tc_flow.prio);

                VLOG_DBG(" **** offloaded! handle: %d (%x)\n", tc_flow.handle,
                         tc_flow.handle);
            } else
                VLOG_ERR(" **** error adding drop rule! tc error: %d\n",
                         error);
        }

        if (error)
            return DPIF_HW_NO_OFFLAOAD;
        return DPIF_HW_OFFLOAD_ONLY;
    }

    VLOG_DBG("RESULT: SW\n");

    return DPIF_HW_NO_OFFLAOAD;
}

static enum dpif_hw_offload_policy
parse_flow_get(struct dpif_hw_acc *dpif, struct dpif_flow_get *get)
{
    struct netdev *in = 0;
    uint16_t prio = 0;
    int handle =
        gethandle(dpif, get->ufid, &in, &prio, "DPIF_OP_FLOW_GET", 1);

    if (handle && prio) {
        struct tc_flow tc_flow;
        int ifindex = netdev_get_ifindex(in);
        int ovs_port = get_ovs_port(dpif, ifindex);
        int error = ENOENT;

        if (ovs_port != -1)
            error = tc_get_flower(ifindex, handle, prio, &tc_flow);

        if (!error) {
            dpif_hw_tc_flow_to_dpif_flow(dpif, &tc_flow, get->flow, ovs_port,
                                         get->buffer, in);
            return DPIF_HW_OFFLOAD_ONLY;
        }
    }

    return DPIF_HW_NO_OFFLAOAD;
}

static enum dpif_hw_offload_policy
parse_flow_del(struct dpif_hw_acc *dpif, struct dpif_flow_del *del)
{
    struct netdev *in = 0;
    uint16_t prio = 0;
    int handle =
        gethandle(dpif, del->ufid, &in, &prio, "DPIF_OP_FLOW_DEL", 1);

    /* we delete the handle anyway (even if not deleted from tc) */
    delhandle(dpif, del->ufid);

    if (handle && prio) {
        int ifindex = netdev_get_ifindex(in);

        VLOG_DBG("deleting ufid %s, handle %d, prio: %d, ifindex: %d\n",
                 printufid(del->ufid), handle, prio, ifindex);
        int error = tc_del_flower(ifindex, handle, prio);

        if (error)
            VLOG_ERR("DELETE FAILED: tc error: %d\n", error);
        else
            VLOG_DBG("DELETE SUCCESS!\n");

        if (error)
            return DPIF_HW_NO_OFFLAOAD;

        return DPIF_HW_OFFLOAD_ONLY;
    }

    VLOG_DBG("del with no handle/ufid/prio, SW only\n");
    return DPIF_HW_NO_OFFLAOAD;
}

static enum dpif_hw_offload_policy
parse_operate(struct dpif_hw_acc *dpif, struct dpif_op *op)
{
    switch (op->type) {
    case DPIF_OP_FLOW_PUT:
        VLOG_DBG("DPIF_OP_FLOW_PUT");
        return parse_flow_put(dpif, &op->u.flow_put);
    case DPIF_OP_FLOW_GET:
        VLOG_DBG("DPIF_OP_FLOW_GET");
        return parse_flow_get(dpif, &op->u.flow_get);
    case DPIF_OP_FLOW_DEL:
        VLOG_DBG("DPIF_OP_FLOW_DEL");
        return parse_flow_del(dpif, &op->u.flow_del);

    case DPIF_OP_EXECUTE:
    default:
        return DPIF_HW_NO_OFFLAOAD;
    }
    return DPIF_HW_NO_OFFLAOAD;
}

static void
dpif_hw_acc_operate(struct dpif *dpif_, struct dpif_op **ops, size_t n_ops)
{
    struct dpif_hw_acc *dpif = dpif_hw_acc_cast(dpif_);

    struct dpif_op **new_ops = xmalloc(sizeof (struct dpif_op *) * n_ops);
    int n_new_ops = 0;
    int i = 0;

    for (i = 0; i < n_ops; i++) {
        if (parse_operate(dpif, ops[i]) == DPIF_HW_OFFLOAD_ONLY) {
            ops[i]->error = 0;
        } else
            new_ops[n_new_ops++] = ops[i];
    }
    dpif->lp_dpif_netlink->dpif_class->operate(dpif->lp_dpif_netlink, new_ops,
                                               n_new_ops);
    free(new_ops);
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
