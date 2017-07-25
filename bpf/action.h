/*
 * Copyright (c) 2016 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#include <errno.h>
#include <stdint.h>
#include <iproute2/bpf_elf.h>
#include <linux/ip.h>

#include "api.h"
#include "conntrack.h"
#include "ipv4.h"
#include "maps.h"
#include "helpers.h"

/*
 * Every OVS action need to lookup the action list and
 * with index, find out the action to process
 */
static inline struct bpf_action *pre_tail_action(struct __sk_buff *skb,
    struct bpf_action_batch **__batch)
{
    uint32_t index = ovs_cb_get_action_index(skb);
    struct bpf_action *action = NULL;
    struct bpf_action_batch *batch;
    struct ebpf_headers_t *headers;
    struct ebpf_metadata_t *mds;
    struct bpf_flow_key flow_key;

    printt("process %dth action\n", index);

    headers = bpf_get_headers();
    if (!headers) {
        printt("no header\n");
        return NULL;
    }

    mds = bpf_get_mds();
    if (!mds) {
        printt("no md\n");
        return NULL;
    }

    flow_key.headers = *headers;
    flow_key.mds = *mds;

    batch = bpf_map_lookup_elem(&flow_table, &flow_key);
    if (!batch) {
        printt("no batch action found\n");
        return NULL;
    }

    // Don't move to the front, verifer bug
    if (index >= BPF_DP_MAX_ACTION)
        return NULL;

    *__batch = batch;
    action = &((batch)->actions[index]); /* currently processing action */
    return action;
}

/*
 * After processing the action, tail call the next.
 */
static inline int post_tail_action(struct __sk_buff *skb,
    struct bpf_action_batch *batch)
{
    struct bpf_action *next_action;
    uint32_t index;

    if (!batch)
        return TC_ACT_SHOT;

    index = skb->cb[OVS_CB_ACT_IDX] + 1;
    skb->cb[OVS_CB_ACT_IDX] = index;

    if (index >= BPF_DP_MAX_ACTION)
        return TC_ACT_SHOT;

    next_action = &batch->actions[index];

    printt("next action type = %d\n", next_action->type);
    bpf_tail_call(skb, &tailcalls, next_action->type);
    printt("[BUG] tail call missing\n");
    return TC_ACT_SHOT;
}

__section_tail(OVS_ACTION_ATTR_UNSPEC)
static int tail_action_unspec(struct __sk_buff *skb)
{
    int index = ovs_cb_get_action_index(skb);
    printt("action index = %d, end of processing\n", index);

    /* if index == 0, this is the first action,
        drop else also drop
     */
    return TC_ACT_SHOT;
}

__section_tail(OVS_ACTION_ATTR_OUTPUT)
static int tail_action_output(struct __sk_buff *skb)
{
    int ret;
    struct bpf_action *action;
    struct bpf_action_batch *batch;
    int flags;

    /* Deparser will update the packet content and metadata */
    ret = ovs_deparser(skb);
    if (ret != 0)
        return TC_ACT_SHOT;

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    printt("output action port = %d\n", action->u.out.port);
    flags = action->u.out.flags & OVS_BPF_FLAGS_TX_STACK ? BPF_F_INGRESS : 0;
    bpf_clone_redirect(skb, action->u.out.port, flags);

    post_tail_action(skb, batch);
    return TC_ACT_SHOT;
}

__section_tail(OVS_ACTION_ATTR_SET)
static int tail_action_tunnel_set(struct __sk_buff *skb)
{
    struct bpf_tunnel_key key;
    int ret;

    struct bpf_action *action;
    struct bpf_action_batch *batch;

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    /* hard-coded now, should fetch it from action->u */
    __builtin_memset(&key, 0x0, sizeof(key));
    key.remote_ipv4 = 0xac100164; /* 172.16.1.100 */
    key.tunnel_id = 2;
    key.tunnel_tos = 0;
    key.tunnel_ttl = 61;

    ret = bpf_skb_set_tunnel_key(skb, &key, sizeof(key), BPF_F_ZERO_CSUM_TX);

    /* FIXME: if there is tunnel_opt then
     *     bpf_skb_set_tunnel_opt();
     */
    if (ret < 0)
        printt("[ERROR] setting tunnel key\n");

    post_tail_action(skb, batch);
    return TC_ACT_SHOT;
}

__section_tail(OVS_ACTION_ATTR_PUSH_VLAN)
static int tail_action_push_vlan(struct __sk_buff *skb)
{
    struct bpf_action *action;
    struct bpf_action_batch *batch;

    // -- Add vlan_tag_t and regenerate P4 --
    //  key->eth.vlan.tci = vlan->vlan_tci;
    //  key->eth.vlan.tpid = vlan->vlan_tpid;
    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    printt("vlan push tci %d\n", action->u.push_vlan.vlan_tci);
    printt("vlan push tpid %d\n", action->u.push_vlan.vlan_tpid);
    bpf_skb_vlan_push(skb, action->u.push_vlan.vlan_tpid,
                           action->u.push_vlan.vlan_tci & ~VLAN_TAG_PRESENT);

    post_tail_action(skb, batch);
    return TC_ACT_SHOT;
}

__section_tail(OVS_ACTION_ATTR_POP_VLAN)
static int tail_action_pop_vlan(struct __sk_buff *skb)
{
    struct bpf_action *action;
    struct bpf_action_batch *batch;

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    printt("vlan pop %d\n");
    bpf_skb_vlan_pop(skb);

    // TODO: invalidate_flow_key()?
    //  key->eth.vlan.tci = 0;
    //  key->eth.vlan.tpid = 0;
    post_tail_action(skb, batch);
    return TC_ACT_SHOT;
}

__section_tail(OVS_ACTION_ATTR_RECIRC)
static int tail_action_recirc(struct __sk_buff *skb)
{
    u32 recirc_id = 0;
    struct bpf_action *action;
    struct bpf_action_batch *batch ;
    struct ebpf_metadata_t *ebpf_md;

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    /* recirc should be the last action.
     * level does not handle */

    /* don't check the is_flow_key_valid(),
     * now always re-parsing the header.
     */
    recirc_id = action->u.recirc_id;
    printt("recirc id = %d\n", recirc_id);

    /* update metadata */
    ebpf_md = bpf_get_mds();
    if (!ebpf_md) {
        printt("lookup metadata failed\n");
        return TC_ACT_SHOT;
    }
    ebpf_md->md.recirc_id = recirc_id;

    /* FIXME: recirc should not call this. */
    // post_tail_action(skb, batch);
    // start from beginning, call the ebpf_filter()
    // but metadata should keep untouched?
    bpf_tail_call(skb, &tailcalls, PARSER_CALL);
    return TC_ACT_SHOT;
}

__section_tail(OVS_ACTION_ATTR_HASH)
static int tail_action_hash(struct __sk_buff *skb)
{
    u32 hash = 0;
    int index = 0;
    struct ebpf_metadata_t *ebpf_md;
    struct bpf_action *action;
    struct bpf_action_batch *batch;

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    printt("skb->hash before = %x\n", skb->hash);
    hash = bpf_get_hash_recalc(skb);
    printt("skb->hash = %x hash \n", skb->hash);
    if (!hash)
        hash = 0x1;

    ebpf_md = bpf_map_lookup_elem(&percpu_metadata, &index);
    if (!ebpf_md) {
        printt("LOOKUP metadata failed\n");
        return TC_ACT_SHOT;
    }
    printt("save hash to ebpf_md->md.dp_hash\n");
    ebpf_md->md.dp_hash = hash; // or create a ovs_flow_hash?

    post_tail_action(skb, batch);
    return TC_ACT_SHOT;
}

/* write to packet's md, let deparser write to packet.
 * currently csum computation isn't supported.
 * here we only handle skb metadata udpate */
__section_tail(OVS_ACTION_ATTR_SET_MASKED)
static int tail_action_set_masked(struct __sk_buff *skb)
{
    struct bpf_action *action;
    struct bpf_action_batch *batch;
    struct ebpf_headers_t *headers OVS_UNUSED = bpf_get_headers();
    struct ebpf_metadata_t *md OVS_UNUSED = bpf_get_mds();

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    printt("set masked action type = %d\n", action->u.mset.key_type);
#if 0
    switch(action->u.mset.key_type) {
    case OVS_KEY_ATTR_ETHERNET: {
        printt("set ethernet\n");
        struct ovs_key_ethernet *ether = &action->u.mset.key.ether;
//        struct ovs_key_ethernet *mask = &action->u.mset.mask.ether;
        if (!ether ) {
            printt("this action is skipped\n");
            goto skip;
        }

        if ((void *)headers->ethernet.dstAddr != NULL &&
            (void *)ether->eth_dst != NULL)
            __builtin_memcpy((void *)headers->ethernet.dstAddr,
                     (void *)ether->eth_dst, 6);
/* BUG? verifier fails.
        if ((void *)headers->ethernet.srcAddr != NULL &&
            (void *)ether->eth_src != NULL)
            __builtin_memcpy((void *)headers->ethernet.srcAddr,
                    (void *)ether->eth_src, 6);
*/
        break;
    }
    case OVS_KEY_ATTR_PRIORITY:
    case OVS_KEY_ATTR_SKB_MARK:
        printt("update skb mark at both md and skb?\n");
    case OVS_KEY_ATTR_IPV4:
        printt("update ipv4\n");
    default:
        printt("field in set mased not supported\n");
        break;
    }
skip:
#endif
    post_tail_action(skb, batch);
    return TC_ACT_SHOT;
}

__section_tail(OVS_ACTION_ATTR_TRUNC)
static int tail_action_trunc(struct __sk_buff *skb)
{
    struct bpf_action *action;
    struct bpf_action_batch *batch;

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    printt("truncate to %d\n", action->u.trunc.max_len);

    /* The helper will resize the skb to the given new size */
    bpf_skb_change_tail(skb, action->u.trunc.max_len, 0);

    post_tail_action(skb, batch);
    return TC_ACT_SHOT;
}

#define SKB_DATA_CAST(x) ((void *)(long)x)

__section_tail(OVS_ACTION_ATTR_CT)
static int tail_action_ct(struct __sk_buff *skb)
{
    struct ipv4_ct_tuple tuple = {};
    struct ct_state ct_state = {};
    void *data = SKB_DATA_CAST(skb->data);
    void *data_end = SKB_DATA_CAST(skb->data_end);

    struct bpf_action_batch *batch;
    struct ebpf_headers_t *headers;
    struct ebpf_metadata_t *md;
    struct bpf_action *action;
    struct iphdr *ipv4;
    int l4_ofs, dir;
    bool commit;
    int res;

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    commit = action->u.ct.commit;

    headers = bpf_get_headers();
    if (!headers) {
        printt("no header\n");
        return TC_ACT_SHOT;
    }

    if (headers->ethernet.etherType != 0x0800) {
        printt("ct: dropping non-IPv4 packet\n");
        return TC_ACT_SHOT;
    }

#define ETH_HLEN 14 /* XXX */

    if (data + sizeof(*ipv4) + ETH_HLEN > data_end) {
        printt("ct: IP packet too short\n");
        return TC_ACT_SHOT;
    }

    ipv4 = (struct iphdr *)(data + ETH_HLEN);
    tuple.daddr = ipv4->daddr;
    tuple.saddr = ipv4->saddr;
    tuple.nexthdr = ipv4->protocol;
    l4_ofs = ETH_HLEN + ipv4_hdrlen(ipv4);
    /* tuple l4 ports are filled by ct_lookup */
    dir = skb->cb[OVS_CB_INGRESS] ? CT_INGRESS : CT_EGRESS;

    res = ct_lookup4(&ct_table4, &tuple, skb, l4_ofs, 0, dir, &ct_state);
    if (res < 0) {
        /* XXX: OVS_CS_F_INVALID */
        printt("ct() err=%d\n", res);
        return TC_ACT_SHOT;
    }
    printt("ct() success=%d\n", res);

    md = bpf_get_mds();
    if (!md) {
        printt("lookup metadata failed\n");
        return TC_ACT_SHOT;
    }
    //md->md.ct_state = OVS_CS_F_TRACKED;

    //switch (res) {
    //case CT_NEW:
    //    md->md.ct_state |= OVS_CS_F_NEW;
    //    break;
    //case CT_ESTABLISHED:
    //    md->md.ct_state |= OVS_CS_F_ESTABLISHED;
    //    break;
    //case CT_RELATED:
    //    md->md.ct_state |= OVS_CS_F_RELATED;
    //    break;
    //case CT_REPLY:
    //    md->md.ct_state |= OVS_CS_F_REPLY_DIR;
    //default:
    //    return TC_ACT_SHOT;
    //}

    /* XXX: Commit, mark, label */
    if (commit) {
        int err;

        printt("ct commit\n");
        err = ct_create4(&ct_table4, &tuple, skb, dir, &ct_state, false);
        if (err) {
            printt("ct creation failed\n");
            return TC_ACT_SHOT;
        }
    }

    /* XXX: NAT, etc. */
    /* XXX: OVS_CS_F_SRC_NAT; OVS_CS_F_DST_NAT */

    post_tail_action(skb, batch);
    return TC_ACT_SHOT;
}
