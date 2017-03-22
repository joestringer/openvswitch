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

#ifndef TC_H
#define TC_H 1

#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include "odp-netlink.h"
#include "netlink-socket.h"

#define TC_POLICY_DEFAULT "none"

unsigned int tc_make_handle(unsigned int major, unsigned int minor);
unsigned int tc_get_major(unsigned int handle);
unsigned int tc_get_minor(unsigned int handle);
struct tcmsg *tc_make_request(int ifindex, int type, unsigned int flags,
                              struct ofpbuf *request);
int tc_transact(struct ofpbuf *request, struct ofpbuf **replyp);
int tc_add_del_ingress_qdisc(int ifindex, bool add);

struct tc_cookie {
    const void *data;
    size_t len;
};

struct tc_flower_key {
    ovs_be16 eth_type;
    uint8_t ip_proto;

    struct eth_addr dst_mac;
    struct eth_addr src_mac;

    ovs_be16 src_port;
    ovs_be16 dst_port;

    uint16_t vlan_id;
    uint8_t vlan_prio;

    ovs_be16 encap_eth_type;

    union {
        struct {
            ovs_be32 ipv4_src;
            ovs_be32 ipv4_dst;
        } ipv4;
        struct {
            struct in6_addr ipv6_src;
            struct in6_addr ipv6_dst;
        } ipv6;
    };
};

struct tc_flower {
    uint32_t handle;
    uint32_t prio;

    struct tc_flower_key key;
    struct tc_flower_key mask;

    uint8_t vlan_pop;
    uint16_t vlan_push_id;
    uint8_t vlan_push_prio;

    int ifindex;
    int ifindex_out;

    struct ovs_flow_stats stats;
    uint64_t lastused;

    struct {
        bool set;
        ovs_be64 id;
        ovs_be16 tp_src;
        ovs_be16 tp_dst;
        struct {
            ovs_be32 ipv4_src;
            ovs_be32 ipv4_dst;
        } ipv4;
        struct {
            struct in6_addr ipv6_src;
            struct in6_addr ipv6_dst;
        } ipv6;
    } set;

    struct {
        bool tunnel;
        struct {
            ovs_be32 ipv4_src;
            ovs_be32 ipv4_dst;
        } ipv4;
        struct {
            struct in6_addr ipv6_src;
            struct in6_addr ipv6_dst;
        } ipv6;
        ovs_be64 id;
        ovs_be16 tp_src;
        ovs_be16 tp_dst;
    } tunnel;

    struct tc_cookie act_cookie;
};

int tc_replace_flower(int ifindex, uint16_t prio, uint32_t handle,
                      struct tc_flower *flower);
int tc_del_filter(int ifindex, int prio, int handle);
int tc_get_flower(int ifindex, int prio, int handle,
                  struct tc_flower *flower);
int tc_flush(int ifindex);
int tc_dump_flower_start(int ifindex, struct nl_dump *dump);
int parse_netlink_to_tc_flower(struct ofpbuf *reply,
                               struct tc_flower *flower);
void tc_set_policy(const char *policy);

#endif /* tc.h */
