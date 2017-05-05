/*
 * Copyright (c) 2016 Nicira, Inc.
 *
 * This file is offered under your choice of two licenses: Apache 2.0 or GNU
 * GPL 2.0 or later.  The permission statements for each of these licenses is
 * given below.  You may license your modifications to this file under either
 * of these licenses or both.  If you wish to license your modifications under
 * only one of these licenses, delete the permission text for the other
 * license.
 *
 * ----------------------------------------------------------------------
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
 * ----------------------------------------------------------------------
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
 * ----------------------------------------------------------------------
 */

#ifndef BPF_OPENVSWITCH_H
#define BPF_OPENVSWITCH_H 1

#include "odp-netlink.h"

enum ovs_upcall_cmd {
    OVS_UPCALL_UNSPEC = OVS_PACKET_CMD_UNSPEC,

    /* Kernel-to-user notifications. */
    OVS_UPCALL_MISS = OVS_PACKET_CMD_MISS,
    OVS_UPCALL_ACTION = OVS_PACKET_CMD_ACTION,

    /* Userspace commands. */
    OVS_UPCALL_EXECUTE = OVS_PACKET_CMD_EXECUTE,

    OVS_UPCALL_DEBUG,
};

enum ovs_dbg_subtype {
    OVS_DBG_ST_UNSPEC,
    OVS_DBG_ST_REDIRECT,
    __OVS_DBG_ST_MAX,
};
#define OVS_DBG_ST_MAX (__OVS_DBG_ST_MAX - 1)

static const char *bpf_upcall_subtypes[] OVS_UNUSED = {
    [OVS_DBG_ST_UNSPEC] = "Unspecified",
    [OVS_DBG_ST_REDIRECT] = "Downcall redirect",
};

/* Used with 'datapath_stats' map. */
enum ovs_bpf_dp_stats {
    OVS_DP_STATS_UNSPEC,
    OVS_DP_STATS_HIT,
    OVS_DP_STATS_MISSED,
    OVS_DP_STATS_LOST,
    OVS_DP_STATS_FLOWS,
    OVS_DP_STATS_MASK_HIT,
    OVS_DP_STATS_MASKS,
    OVS_DP_STATS_ERRORS,
    __OVS_DP_STATS_MAX,
};
#define OVS_DP_STATS_MAX (__OVS_DP_STATS_MAX - 1)

struct bpf_flow {
    uint64_t value;             /* XXX */
};

struct bpf_upcall {
    uint8_t type;
    uint8_t subtype;
    uint32_t ifindex;           /* Incoming device */
    uint32_t cpu;
    uint32_t error;
    uint32_t skb_len;
    /* Followed by 'skb_len' of packet data. */
};

#define OVS_BPF_FLAGS_TX_STACK (1 << 0)

struct bpf_downcall {
    uint32_t debug;
    uint32_t ifindex;
    uint32_t flags;
    /* Followed by packet data. */
};

#endif /* BPF_OPENVSWITCH_H */
