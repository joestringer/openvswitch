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

#include "api.h"
#include "odp-bpf.h"

/* We don't rely on specific versions of the kernel; however libbpf requires
 * this to be both specified and non-zero. */
static const __maybe_unused __section("version") uint32_t version = 0x1;

BPF_HASH(flow_table,
         0,
         sizeof(uint64_t),
         sizeof(struct bpf_flow),
         PIN_GLOBAL_NS,
         1
);
BPF_PERF_OUTPUT(upcalls, PIN_GLOBAL_NS);

/* XXX: Percpu */
BPF_ARRAY(datapath_stats,
          0,
          sizeof(uint64_t),
          PIN_GLOBAL_NS,
          __OVS_DP_STATS_MAX
);

static inline void __maybe_unused
bpf_debug(struct __sk_buff *skb, enum ovs_dbg_subtype subtype, int error)
{
    uint64_t cpu = get_smp_processor_id();
    uint64_t flags = skb->len;
    struct bpf_upcall md = {
        .type = OVS_UPCALL_DEBUG,
        .subtype = subtype,
        .ifindex = skb->ingress_ifindex,
        .cpu = cpu,
        .skb_len = skb->len,
        .error = error
    };

    flags <<= 32;
    flags |= BPF_F_CURRENT_CPU;

    skb_event_output(skb, &upcalls, flags, &md, sizeof(md));
}

static inline void
stats_account(enum ovs_bpf_dp_stats index)
{
    uint32_t stat = 1;
    uint64_t *value;

    value = map_lookup_elem(&datapath_stats, &index);
    if (value) {
        __sync_fetch_and_add(value, stat);
    }
}

static inline int process(struct __sk_buff *skb, int ifindex)
{
    uint64_t flags = skb->len;
    struct bpf_upcall md = {
        .type = OVS_UPCALL_MISS,
        .ifindex = ifindex,
        .skb_len = skb->len,
    };
    int stat, err;

    flags <<= 32;
    flags |= BPF_F_CURRENT_CPU;

    err = skb_event_output(skb, &upcalls, flags, &md, sizeof(md));
    stat = !err ? OVS_DP_STATS_MISSED
                : err == -ENOSPC ? OVS_DP_STATS_LOST
                                 : OVS_DP_STATS_ERRORS;
    stats_account(stat);
    return TC_ACT_OK;
}

__section("ingress")
static int to_stack(struct __sk_buff *skb)
{
    printt("ingress from %d (%d)\n", skb->ingress_ifindex, skb->ifindex);
    return process(skb, skb->ingress_ifindex);
}

__section("egress")
static int from_stack(struct __sk_buff *skb)
{
    printt("egress from %d (%d)\n", skb->ingress_ifindex, skb->ifindex);
    return process(skb, skb->ifindex);
}

__section("downcall")
static int execute(struct __sk_buff *skb)
{
    struct bpf_downcall md;
    int flags, ofs;

    ofs = skb->len - sizeof(md);
    skb_load_bytes(skb, ofs, &md, sizeof(md));
    flags = md.flags & OVS_BPF_FLAGS_TX_STACK ? BPF_F_INGRESS : 0;

    printt("downcall from %d -> %d (%d)\n", skb->ingress_ifindex, md.ifindex,
           flags);

    skb_change_tail(skb, ofs, 0);

    return redirect(md.ifindex, flags);
}

BPF_LICENSE("GPL");
