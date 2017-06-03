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
