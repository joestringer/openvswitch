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

/* Instead of having multiple BPF object files,
 * include all headers and generate one datapath.o
 */
#include "maps.h"
#include "parser.h"
#include "lookup.h"
#include "deparser.h"
#include "action.h"

/* We don't rely on specific versions of the kernel; however libbpf requires
 * this to be both specified and non-zero. */
static const __maybe_unused __section("version") uint32_t version = 0x1;

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

__section_tail(UPCALL_CALL)
static inline int process_upcall(struct __sk_buff *skb) //remove ifindex
{
    uint64_t flags = skb->len;
    struct bpf_upcall md = {
        .type = OVS_UPCALL_MISS,
        .skb_len = skb->len,
        .ifindex = skb->ingress_ifindex,
    };
    int stat, err;
    struct ebpf_headers_t *hdrs = bpf_get_headers();
    struct ebpf_metadata_t *mds = bpf_get_mds();

    if (!skb)
        return TC_ACT_OK;

    if (!hdrs || !mds) {
        printt("headers/mds is NULL\n");
        return TC_ACT_OK;
    }

    if (hdrs->icmp.valid)
        printk("upcall ICMP packet\n");

    // memset(&md, 0, sizeof(md));
    memcpy(&md.key.headers, hdrs, sizeof(struct ebpf_headers_t));
    memcpy(&md.key.mds, mds, sizeof(struct ebpf_metadata_t));

    flags <<= 32;
    flags |= BPF_F_CURRENT_CPU;

    printt("upcall skb->len %d md len %d\n", skb->len, sizeof(md));

    err = skb_event_output(skb, &upcalls, flags, &md, sizeof(md));
    stat = !err ? OVS_DP_STATS_MISSED
                : err == -ENOSPC ? OVS_DP_STATS_LOST
                                 : OVS_DP_STATS_ERRORS;
    stats_account(stat);
    return TC_ACT_OK;
}

static void cb_init(struct __sk_buff *skb)
{
    int i;
    for (i = 0; i < 5; i++)
        skb->cb[i] = 0;
}

/* ENTRY POINT */
__section("ingress")
static int to_stack(struct __sk_buff *skb)
{
    printt("ingress from %d (%d)\n", skb->ingress_ifindex, skb->ifindex);

    cb_init(skb);
    bpf_tail_call(skb, &tailcalls, PARSER_CALL);

    printt("[ERROR] tail call fail\n");
    return TC_ACT_OK;
}

__section("egress")
static int from_stack(struct __sk_buff *skb)
{
    printt("egress from %d (%d)\n", skb->ingress_ifindex, skb->ifindex);
    bpf_tail_call(skb, &tailcalls, UPCALL_CALL);
    printt("[ERROR] tail call fail\n");
    return 0;
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
