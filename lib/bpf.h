/*
 * Copyright (c) 2016 Nicira, Inc.
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

#ifndef LIB_BPF_H
#define LIB_BPF_H 1

#include <errno.h>
#include "openvswitch/compiler.h"

#define INGRESS_HANDLE     0xFFFFFFF2
#define EGRESS_HANDLE      0xFFFFFFF3

struct bpf_prog {
    const char *name;
    uint32_t handle;            /* tc handle */
    int fd;
};

struct bpf_map {
    const char *name;
    int fd;
};

#if HAVE_BPF
struct bpf_state;
struct ds;

struct bpf_state {
    /* File descriptors for programs. */
    struct bpf_prog ingress;            /* BPF_PROG_TYPE_SCHED_CLS */
    struct bpf_prog egress;             /* BPF_PROG_TYPE_SCHED_CLS */
    struct bpf_prog downcall;           /* BPF_PROG_TYPE_SCHED_CLS */
    struct bpf_map upcalls;             /* BPF_MAP_TYPE_PERF_ARRAY */
    struct bpf_map flow_table;          /* BPF_MAP_TYPE_HASH */
    struct bpf_map datapath_stats;      /* BPF_MAP_TYPE_ARRAY */
};

int bpf_get(struct bpf_state *state, bool verbose);
void bpf_put(struct bpf_state *state);
int bpf_load(const char *path);
void bpf_init(void);
void bpf_format_state(struct ds *ds, struct bpf_state *state);
#else /* !HAVE_BPF */
static inline int bpf_load(const char *path OVS_UNUSED) { return EOPNOTSUPP; }
static inline void bpf_init(void) { }
#endif /* HAVE_BPF */

#endif /* LIB_BPF_H */
