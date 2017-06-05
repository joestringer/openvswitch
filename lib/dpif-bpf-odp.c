/*
 * Copyright (c) 2017 Nicira, Inc.
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

#include "dpif-bpf-odp.h"

#include <errno.h>

#include "bpf/odp-bpf.h"
#include "openvswitch/flow.h"
#include "openvswitch/vlog.h"
#include "netlink.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(dpif_bpf_odp);

/* Converts the OVS netlink-formatted action 'src' into a BPF action in 'dst'.
 *
 * Returns 0 on success, or a positive errno value on failure.
 */
int
odp_action_to_bpf_action(const struct nlattr *src, struct bpf_action *dst)
{
    enum ovs_action_attr type = nl_attr_type(src);

    switch (type) {
    case OVS_ACTION_ATTR_PUSH_VLAN: {
        const struct ovs_action_push_vlan *vlan = nl_attr_get(src);
        dst->u.push_vlan = *vlan;
        VLOG_DBG("push vlan tpid %x tci %x", vlan->vlan_tpid, vlan->vlan_tci);
        break;
    }
    case OVS_ACTION_ATTR_USERSPACE:
    case OVS_ACTION_ATTR_SET:
    case OVS_ACTION_ATTR_POP_VLAN:
    case OVS_ACTION_ATTR_SAMPLE:
    case OVS_ACTION_ATTR_RECIRC:
    case OVS_ACTION_ATTR_HASH:
    case OVS_ACTION_ATTR_PUSH_MPLS:
    case OVS_ACTION_ATTR_POP_MPLS:
    case OVS_ACTION_ATTR_SET_MASKED:
    case OVS_ACTION_ATTR_CT:
    case OVS_ACTION_ATTR_TRUNC:
    case OVS_ACTION_ATTR_PUSH_ETH:
    case OVS_ACTION_ATTR_POP_ETH:
    case OVS_ACTION_ATTR_TUNNEL_PUSH:
    case OVS_ACTION_ATTR_TUNNEL_POP:
    case OVS_ACTION_ATTR_CLONE:
    case OVS_ACTION_ATTR_METER:
        VLOG_WARN("Unsupported action type %d",  nl_attr_type(src));
        return EOPNOTSUPP;
    case OVS_ACTION_ATTR_UNSPEC:
    case OVS_ACTION_ATTR_OUTPUT:
    case __OVS_ACTION_ATTR_MAX:
        OVS_NOT_REACHED();
    }

    return 0;
}

/* Extracts packet metadata from the BPF-formatted flow key in 'key' into a
 * flow structure in 'flow'. Returns an ODP_FIT_* value that indicates how well
 * 'key' fits our expectations for what a flow key should contain.
 */
enum odp_key_fitness
bpf_flow_key_to_flow(const struct bpf_flow_key *key, struct flow *flow)
{
    const struct pkt_metadata_t *md = &key->mds.md;

    memset(flow, 0, sizeof *flow);

    /* XXX: Populate key. */

    /* metadata parsing */
    flow->in_port.odp_port = u32_to_odp(md->in_port);
    flow->recirc_id = md->recirc_id;
    flow->dp_hash = md->dp_hash;
    flow->skb_priority = md->skb_priority;
    flow->pkt_mark = md->pkt_mark;
    flow->ct_state = md->ct_state;
    flow->ct_zone = md->ct_zone;
    flow->ct_mark = md->ct_mark;
    /* TODO */
    /*
    flow->ct_label = md.ct_label;
    flow_tnl_copy__()
    */
    return ODP_FIT_PERFECT;
}

/* Converts the 'nla_len' bytes of OVS netlink-formatted flow key in 'nla' into
 * the bpf flow structure in 'key'. Returns an ODP_FIT_* value that indicates
 * how well 'nla' fits into the BPF flow key format. On success, 'in_port' will
 * be populated with the in_port specified by 'nla', which the caller must
 * convert from an ODP port number into an ifindex and place into 'key'.
 */
enum odp_key_fitness
odp_key_to_bpf_flow_key(const struct nlattr *nla, size_t nla_len,
                        struct bpf_flow_key *key, odp_port_t *in_port)
{
    bool found_in_port = false;
    const struct nlattr *a;
    size_t left;

    NL_ATTR_FOR_EACH_UNSAFE(a, left, nla, nla_len) {
        enum ovs_key_attr type = nl_attr_type(a);

        switch (type) {
        case OVS_KEY_ATTR_PRIORITY:
            key->mds.md.skb_priority = nl_attr_get_u32(a);
            break;
        case OVS_KEY_ATTR_IN_PORT: {
            /* The caller must convert the ODP port number into ifindex. */
            *in_port = nl_attr_get_odp_port(a);
            found_in_port = true;
            break;
        }
        case OVS_KEY_ATTR_ETHERNET: {
            const struct ovs_key_ethernet *eth = nl_attr_get(a);

            for (int i = 0; i < ARRAY_SIZE(eth->eth_dst.ea); i++) {
                key->headers.ethernet.dstAddr[i] = eth->eth_dst.ea[i];
                key->headers.ethernet.srcAddr[i] = eth->eth_src.ea[i];
            }
            key->headers.ethernet.valid = 1;
            break;
        }
        case OVS_KEY_ATTR_VLAN: {
            ovs_be16 tci = nl_attr_get_be16(a);

            key->headers.vlan.pcp = vlan_tci_to_pcp(tci);
            key->headers.vlan.cfi = vlan_tci_to_cfi(tci);
            key->headers.vlan.vid = vlan_tci_to_vid(tci);
            /* XXX: Ethertype */
            key->headers.vlan.valid = 1;
            break;
        }
        case OVS_KEY_ATTR_ETHERTYPE:
            /* XXX: etherType to set depends on encapsulation. */
            key->headers.ethernet.etherType = ntohs(nl_attr_get_be16(a));
            key->headers.ethernet.valid = 1;
            break;
        case OVS_KEY_ATTR_IPV4: {
            const struct ovs_key_ipv4 *ipv4 = nl_attr_get(a);

            key->headers.ipv4.srcAddr = ntohl(ipv4->ipv4_src);
            key->headers.ipv4.dstAddr = ntohl(ipv4->ipv4_dst);
            key->headers.ipv4.protocol = ipv4->ipv4_proto;
            key->headers.ipv4.diffserv = ipv4->ipv4_tos;
            key->headers.ipv4.ttl = ipv4->ipv4_ttl;
            /* XXX: ipv4->ipv4_frag; One of OVS_FRAG_TYPE_*. */
            key->headers.ipv4.valid = 1;
            break;
        }
        case OVS_KEY_ATTR_IPV6: {
            const struct ovs_key_ipv6 *ipv6 = nl_attr_get(a);

            memcpy(&key->headers.ipv6.srcAddr, &ipv6->ipv6_src,
                   ARRAY_SIZE(key->headers.ipv6.srcAddr));
            memcpy(&key->headers.ipv6.dstAddr, &ipv6->ipv6_dst,
                   ARRAY_SIZE(key->headers.ipv6.dstAddr));
            key->headers.ipv6.flowLabel = ntohl(ipv6->ipv6_label);
	    key->headers.ipv6.nextHdr = ipv6->ipv6_proto;
	    key->headers.ipv6.trafficClass = ipv6->ipv6_tclass;
	    key->headers.ipv6.hopLimit = ipv6->ipv6_hlimit;
	    /* XXX: ipv6_frag;	One of OVS_FRAG_TYPE_*. */
            key->headers.ipv6.valid = 1;
            break;
        }
        case OVS_KEY_ATTR_TCP: {
            const struct ovs_key_tcp *tcp = nl_attr_get(a);

            key->headers.tcp.srcPort = ntohs(tcp->tcp_src);
            key->headers.tcp.dstPort = ntohs(tcp->tcp_dst);
            key->headers.tcp.valid = 1;
            break;
        }
        case OVS_KEY_ATTR_UDP: {
            const struct ovs_key_udp *udp = nl_attr_get(a);

            key->headers.udp.srcPort = ntohs(udp->udp_src);
            key->headers.udp.dstPort = ntohs(udp->udp_dst);
            key->headers.udp.valid = 1;
            break;
        }
        case OVS_KEY_ATTR_ICMP: {
            const struct ovs_key_icmp *icmp = nl_attr_get(a);

            /* XXX: Double-check */
            key->headers.icmp.typeCode = icmp->icmp_code;
            key->headers.icmp.typeCode |= (uint16_t)icmp->icmp_type << 8;
            key->headers.icmp.valid = 1;
            break;
        }
        case OVS_KEY_ATTR_ARP: {
            const struct ovs_key_arp *arp = nl_attr_get(a);

	    key->headers.arp.opcode = ntohs(arp->arp_op);
	    /* arp->arp_sip; */
	    /* arp->arp_tip; */
	    /* arp->arp_sha; */
	    /* arp->arp_tha; */
            return ODP_FIT_ERROR;
        }
        case OVS_KEY_ATTR_SKB_MARK:
            key->mds.md.pkt_mark = nl_attr_get_u32(a);
            break;
        case OVS_KEY_ATTR_TCP_FLAGS: {
            ovs_be16 flags_be = nl_attr_get_be16(a);
            uint16_t flags = htons(flags_be);

            key->headers.tcp.flags = flags;
            key->headers.tcp.res = flags >> 8;
            key->headers.tcp.valid = 1;
            break;
        }
        case OVS_KEY_ATTR_DP_HASH:
            key->mds.md.dp_hash = nl_attr_get_u32(a);
            break;
        case OVS_KEY_ATTR_RECIRC_ID:
            key->mds.md.recirc_id = nl_attr_get_u32(a);
            break;
        case OVS_KEY_ATTR_CT_STATE:
            key->mds.md.ct_state = nl_attr_get_u32(a);
            break;
        case OVS_KEY_ATTR_CT_ZONE:
            key->mds.md.ct_zone = nl_attr_get_u16(a);
            break;
        case OVS_KEY_ATTR_CT_MARK:
            key->mds.md.ct_mark = nl_attr_get_u32(a);
            break;
        case OVS_KEY_ATTR_CT_LABELS:
            memcpy(&key->mds.md.ct_label, nl_attr_get(a),
                   sizeof(key->mds.md.ct_label));
            break;
        case OVS_KEY_ATTR_ENCAP:
        case OVS_KEY_ATTR_ICMPV6:
        case OVS_KEY_ATTR_ND:
        case OVS_KEY_ATTR_TUNNEL:
        case OVS_KEY_ATTR_SCTP:
        case OVS_KEY_ATTR_MPLS:
        case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4:
        case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6:
        case OVS_KEY_ATTR_PACKET_TYPE:
            return ODP_FIT_ERROR;
        case OVS_KEY_ATTR_UNSPEC:
        case __OVS_KEY_ATTR_MAX:
        default:
            OVS_NOT_REACHED();
        }
    }

    if (!found_in_port) {
        return ODP_FIT_ERROR;
    }

    {
        struct ds ds = DS_EMPTY_INITIALIZER;

        bpf_flow_key_format(&ds, key);
        VLOG_INFO("%s\n%s", __func__, ds_cstr(&ds));

        ds_destroy(&ds);
    }

    return ODP_FIT_PERFECT;
}

void
bpf_flow_key_format(struct ds *ds, const struct bpf_flow_key *key)
{
    ds_put_hex_dump(ds, key, sizeof(*key), 0, true);
}
