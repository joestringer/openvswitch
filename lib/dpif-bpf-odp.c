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
void
bpf_flow_key_extract_metadata(const struct bpf_flow_key *key,
                              struct flow *flow)
{
    const struct pkt_metadata_t *md = &key->mds.md;

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
}

enum odp_key_fitness
bpf_flow_key_to_flow(const struct bpf_flow_key *key, struct flow *flow)
{
    memset(flow, 0, sizeof *flow);

    /* XXX: Populate key. */

    bpf_flow_key_extract_metadata(key, flow);

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
                        struct bpf_flow_key *key, odp_port_t *in_port,
                        bool verbose)
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

    if (verbose) {
        struct ds ds = DS_EMPTY_INITIALIZER;

        bpf_flow_key_format(&ds, key);
        VLOG_INFO("%s\n%s", __func__, ds_cstr(&ds));

        ds_destroy(&ds);
    }

    return ODP_FIT_PERFECT;
}

#define TABSPACE "  "

static void
indent(struct ds *ds, struct ds *tab, const char *string)
{
    ds_put_format(ds, "%s%s", ds_cstr(tab), string);
    ds_put_cstr(tab, TABSPACE);
}

static void
trim(struct ds *ds, struct ds *tab)
{
    ds_chomp(ds, '\n');
    ds_put_char(ds, '\n');
    ds_truncate(tab, tab->length ? tab->length - strlen(TABSPACE) : 0);
}

#define PUT_FIELD(STRUCT, NAME, FORMAT)                               \
    if (STRUCT->NAME)                                                   \
        ds_put_format(ds, #NAME"=%"FORMAT",", STRUCT->NAME)

void
bpf_flow_key_format(struct ds *ds, const struct bpf_flow_key *key)
{
    struct ds tab = DS_EMPTY_INITIALIZER;

    indent(ds, &tab, "headers:\n");
    {
        if (key->headers.ethernet.valid) {
            const struct ethernet_t *eth = &key->headers.ethernet;
            const struct eth_addr *src = (struct eth_addr *)&eth->srcAddr;
            const struct eth_addr *dst = (struct eth_addr *)&eth->dstAddr;

            ds_put_format(ds, "%sethernet(", ds_cstr(&tab));
            PUT_FIELD(eth, etherType, "#"PRIx16);
            ds_put_format(ds, "dst="ETH_ADDR_FMT",", ETH_ADDR_ARGS(*dst));
            ds_put_format(ds, "src="ETH_ADDR_FMT",", ETH_ADDR_ARGS(*src));
            ds_chomp(ds, ',');
            ds_put_format(ds, ")\n");
        }
        if (key->headers.ipv4.valid) {
            const struct ipv4_t *ipv4 = &key->headers.ipv4;

            ds_put_format(ds, "%sipv4(", ds_cstr(&tab));
            PUT_FIELD(ipv4, version, "#"PRIx8);
            PUT_FIELD(ipv4, version, "#"PRIx8);
            PUT_FIELD(ipv4, ihl, "#"PRIx8);
            PUT_FIELD(ipv4, diffserv, "#"PRIx8);
            PUT_FIELD(ipv4, totalLen, "#"PRIx16);
            PUT_FIELD(ipv4, identification, "#"PRIx16);
            PUT_FIELD(ipv4, flags, "#"PRIx8);
            PUT_FIELD(ipv4, fragOffset, "#"PRIx16);
            PUT_FIELD(ipv4, ttl, "#"PRIx8);
            PUT_FIELD(ipv4, protocol, "#"PRIx8);
            PUT_FIELD(ipv4, hdrChecksum, "#"PRIx16);
            ds_put_format(ds, "srcAddr="IP_FMT",", IP_ARGS(ipv4->srcAddr));
            ds_put_format(ds, "dstAddr="IP_FMT",", IP_ARGS(ipv4->dstAddr));
            ds_chomp(ds, ',');
            ds_put_format(ds, ")\n");
        }
        if (key->headers.ipv6.valid) {
            const struct ipv6_t *ipv6 = &key->headers.ipv6;

            ds_put_format(ds, "%sipv6(", ds_cstr(&tab));
            PUT_FIELD(ipv6, version, "#"PRIx8);
            PUT_FIELD(ipv6, trafficClass, "#"PRIx8);
            PUT_FIELD(ipv6, flowLabel, "#"PRIx32);
            PUT_FIELD(ipv6, payloadLen, "#"PRIx16);
            PUT_FIELD(ipv6, nextHdr, "#"PRIx8);
            PUT_FIELD(ipv6, hopLimit, "#"PRIx8);
            ds_put_cstr(ds, "src=");
            ipv6_format_addr((struct in6_addr *)&ipv6->srcAddr, ds);
            ds_put_cstr(ds, ",dst=");
            ipv6_format_addr((struct in6_addr *)&ipv6->dstAddr, ds);
            ds_chomp(ds, ',');
            ds_put_format(ds, ")\n");
        }
        if (key->headers.arp.valid) {
            const struct arp_rarp_t *arp = &key->headers.arp;

            ds_put_format(ds, "%sarp(", ds_cstr(&tab));
            PUT_FIELD(arp, hwType, "#"PRIx16);
            PUT_FIELD(arp, protoType, "#"PRIx16);
            PUT_FIELD(arp, hwAddrLen, "#"PRIx8);
            PUT_FIELD(arp, protoAddrLen, "#"PRIx8);
            PUT_FIELD(arp, opcode, "#"PRIx16);
            ds_chomp(ds, ',');
            ds_put_format(ds, ")\n");
        }
        if (key->headers.tcp.valid) {
            const struct tcp_t *tcp = &key->headers.tcp;

            ds_put_format(ds, "%stcp(", ds_cstr(&tab));
            PUT_FIELD(tcp, srcPort, PRIu16);
            PUT_FIELD(tcp, dstPort, PRIu16);
            PUT_FIELD(tcp, seqNo, "#"PRIx32);
            PUT_FIELD(tcp, ackNo, "#"PRIx32);
            PUT_FIELD(tcp, dataOffset, "#"PRIx8);
            PUT_FIELD(tcp, res, "#"PRIx8);
            PUT_FIELD(tcp, flags, "#"PRIx8);
            PUT_FIELD(tcp, window, "#"PRIx16);
            PUT_FIELD(tcp, checksum, "#"PRIx16);
            PUT_FIELD(tcp, urgentPtr, "#"PRIx16);
            ds_chomp(ds, ',');
            ds_put_format(ds, ")\n");
        }
        if (key->headers.udp.valid) {
            const struct udp_t *udp = &key->headers.udp;

            ds_put_format(ds, "%sudp(", ds_cstr(&tab));
            PUT_FIELD(udp, srcPort, PRIu16);
            PUT_FIELD(udp, dstPort, PRIu16);
            PUT_FIELD(udp, length_, "#"PRIx16);
            PUT_FIELD(udp, checksum, "#"PRIx16);
            ds_chomp(ds, ',');
            ds_put_format(ds, ")\n");
        }
        if (key->headers.icmp.valid) {
            const struct icmp_t *icmp = &key->headers.icmp;

            ds_put_format(ds, "%sicmp(", ds_cstr(&tab));
            PUT_FIELD(icmp, typeCode, "#"PRIx16);
            PUT_FIELD(icmp, hdrChecksum, "#"PRIx16);
            ds_chomp(ds, ',');
            ds_put_format(ds, ")\n");
        }
        if (key->headers.vlan.valid) {
            const struct vlan_tag_t *vlan = &key->headers.vlan;

            ds_put_format(ds, "%svlan(", ds_cstr(&tab));
            PUT_FIELD(vlan, pcp, "#"PRIx8);
            PUT_FIELD(vlan, cfi, "#"PRIx8);
            PUT_FIELD(vlan, vid, "#"PRIx16);
            PUT_FIELD(vlan, etherType, "#"PRIx16);
            ds_chomp(ds, ',');
            ds_put_format(ds, ")\n");
        }
    }
    trim(ds, &tab);
    indent(ds, &tab, "metadata:\n");
    {
        indent(ds, &tab, "standard_metadata:\n");
        {
            ds_put_hex_dump(ds, &key->mds.standard_metadata,
                            sizeof key->mds.standard_metadata, 0, false);
        }
        trim(ds, &tab);
        indent(ds, &tab, "md:\n");
        {
            ds_put_hex_dump(ds, &key->mds.md, sizeof key->mds.md, 0, false);
        }
        trim(ds, &tab);
        indent(ds, &tab, "tnl_md:\n");
        {
            ds_put_hex_dump(ds, &key->mds.tnl_md, sizeof key->mds.tnl_md, 0,
                            false);
        }
        trim(ds, &tab);
    }
    trim(ds, &tab);
    ds_chomp(ds, '\n');

    ds_destroy(&tab);
}
