#ifndef TC_H
#define TC_H 1

#include "odp-netlink.h"

/* tca flags definitions */
#define TCA_CLS_FLAGS_SKIP_HW	(1 << 0)
#define TCA_CLS_FLAGS_SKIP_SW	(1 << 1)
#define TCA_FLOWER_MAX (__TCA_FLOWER_MAX - 1)
struct netdev;

struct tc_flow {
    uint32_t handle;
    uint32_t prio;

    odp_port_t ovs_inport;
    odp_port_t ovs_outport;

    struct netdev *indev;
    struct netdev *outdev;
    int ifindex;
    int ifindex_out;

    ovs_be16 eth_type;
    uint8_t ip_proto;

    struct eth_addr dst_mac;
    struct eth_addr dst_mac_mask;
    struct eth_addr src_mac;
    struct eth_addr src_mac_mask;

    uint16_t src_port;
    uint16_t src_port_mask;
    uint16_t dst_port;
    uint16_t dst_port_mask;

    uint8_t vlan_pop;
    uint16_t vlan_push_id;
    uint8_t vlan_push_prio;
    uint16_t vlan_id;
    uint8_t vlan_prio;
    ovs_be16 encap_eth_type;
    uint8_t encap_ip_proto;
    union {
        struct {
            ovs_be32 ipv4_src;
            ovs_be32 ipv4_src_mask;
            ovs_be32 ipv4_dst;
            ovs_be32 ipv4_dst_mask;
        } encap_ipv4;
        struct {
            ovs_be32 ipv6_src[4];
            ovs_be32 ipv6_src_mask[4];
            ovs_be32 ipv6_dst[4];
            ovs_be32 ipv6_dst_mask[4];
        } encap_ipv6;
    };

    union {
        struct {
            ovs_be32 ipv4_src;
            ovs_be32 ipv4_src_mask;
            ovs_be32 ipv4_dst;
            ovs_be32 ipv4_dst_mask;
        } ipv4;
        struct {
            ovs_be32 ipv6_src[4];
            ovs_be32 ipv6_src_mask[4];
            ovs_be32 ipv6_dst[4];
            ovs_be32 ipv6_dst_mask[4];
        } ipv6;
    };

    struct ovs_flow_stats stats;
    uint64_t lastused;
};

int tc_replace_flower(struct tc_flow *flow, uint16_t prio);
int tc_del_flower(int ifindex, int handle, int prio);
int tc_get_flower(int ifindex, int handle, int prio, struct tc_flow *tc_flow);
int tc_flush_flower(int ifindex);
int tc_dump_flower_start(int ifindex, struct nl_dump *dump);
int parse_tc_flow(struct ofpbuf *reply, struct tc_flow *tc_flow);
void tc_set_skip_hw(bool set);

#endif /* tc.h */
