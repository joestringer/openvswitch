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
#include <openvswitch/compiler.h>
#include "ovs-p4.h"
#include "api.h"
#include "helpers.h"
#include "maps.h"

/* ovs_execute_action:
 * Retrieve the first action, then its tail call
 * exec_action should be a tail_call, because of recirculation
 * can directly call here to avoid parsing twice?
 */
static inline void ovs_execute_actions(struct __sk_buff *skb,
                                       struct bpf_action *action)
{
    int type;

    type = action->type;

    printt("action type %d\n", type);
	/* note: this isn't a for loop, tail call won't return. */
    switch (type) {
    case OVS_ACTION_ATTR_UNSPEC:    //0
        printt("end of action processing\n");
        break;

    case OVS_ACTION_ATTR_OUTPUT: {  //1
        printt("output action port = %d\n", action->u.out.port);
        break;
    }
    case OVS_ACTION_ATTR_PUSH_VLAN: { //4
        printt("vlan push tci %d\n", action->u.push_vlan.vlan_tci);
        break;
    }
    case OVS_ACTION_ATTR_POP_VLAN: { //5
        printt("vlan pop\n");
        break;
    }
    case OVS_ACTION_ATTR_RECIRC: { //7
        printt("recirc\n");
        break;
    }
    case OVS_ACTION_ATTR_HASH: { //8
        printt("hash\n");
        break;
    }
    case OVS_ACTION_ATTR_SET_MASKED: { //11
        printt("set masked\n");
        break;
    }
    case OVS_ACTION_ATTR_TRUNC: { //13
        printt("truncate\n");
        break;
    }
    default:
        printt("action type %d not support\n", type);
        break;
    }
    bpf_tail_call(skb, &tailcalls, type);
    return;
}

static inline struct bpf_action_batch *
ovs_lookup_flow(struct ebpf_headers_t *headers,
                struct ebpf_metadata_t *mds)
{
    struct bpf_flow_key flow_key;

    flow_key.headers = *headers;
    flow_key.mds = *mds;

    return bpf_map_lookup_elem(&flow_table, &flow_key);
}

/* first function called after tc ingress */
__section_tail(MATCH_ACTION_CALL)
static int lookup(struct __sk_buff* skb OVS_UNUSED)
{
    struct bpf_action_batch *action_batch;
    struct bpf_action first_action;
    struct ebpf_headers_t *headers;
    struct ebpf_metadata_t *mds;

    headers = bpf_get_headers();
    if (!headers) {
        printt("no header\n");
        ERR_EXIT();
    }

    mds = bpf_get_mds();
    if (!mds) {
        printt("no md\n");
        ERR_EXIT();
    }

    action_batch = ovs_lookup_flow(headers, mds);
    if (!action_batch) {
        printt("no action found, upcall\n");
        bpf_tail_call(skb, &tailcalls, UPCALL_CALL);
        return TC_ACT_OK;// this is tricky.
    }
    else {
        printt("found action\n");
    }

    first_action = action_batch->actions[0];

    /* the subsequent actions will be tail called. */
    ovs_execute_actions(skb, &first_action);

    //ovs_flow_stats_update(skb);
    printt("ERROR: tail call fails\n");
    return TC_ACT_OK;
}
