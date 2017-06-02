/*
 * Copyright (c) 2017 Nicira, Inc.
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

#include "openvswitch/compiler.h"
#include "odp-bpf.h"

#define SKB_CB_U32S 5   /* According to linux/bpf.h. */

struct ovs_cb {
    uint8_t act_idx;    /* Next action to process in action batch. */
    bool ingress;    /* 0 = egress; nonzero = ingress. */
};
BUILD_ASSERT_DECL(sizeof(struct ovs_cb) < sizeof(__u32) * SKB_CB_U32S);
BUILD_ASSERT_DECL(BPF_DP_MAX_ACTION < 256); /* uint8_t act_idx */

static void
ovs_cb_init(struct __sk_buff *skb, bool ingress OVS_UNUSED)
{
    struct ovs_cb *cb = (struct ovs_cb *)skb->cb;
    int i;

    for (i = 0; i < SKB_CB_U32S; i++)
        skb->cb[i] = 0;
    cb->ingress = ingress;
}

static bool
ovs_cb_is_initial_parse(struct __sk_buff *skb) {
    struct ovs_cb *cb = (struct ovs_cb *)skb->cb;

    if (cb->act_idx != 0) {
        printt("recirc, don't update metadata, index %d\n", cb->act_idx);
    }
    return cb->act_idx == 0;
}

static uint32_t
ovs_cb_get_action_index(struct __sk_buff *skb)
{
    struct ovs_cb *cb = (struct ovs_cb *)skb->cb;

    return cb->act_idx;
}

static uint32_t
ovs_cb_get_ifindex(struct __sk_buff *skb)
{
    struct ovs_cb *cb;

    if (!skb)
        return 0;

    cb = (struct ovs_cb *)skb->cb;
    if (cb->ingress) {
        return skb->ingress_ifindex;
    }

    return skb->ifindex;
}
