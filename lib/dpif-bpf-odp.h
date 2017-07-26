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

#ifndef DPIF_BPF_ODP_H
#define DPIF_BPF_ODP_H 1

#include "odp-util.h"

struct flow;
struct nlattr;
struct bpf_flow_key;
struct bpf_action;
struct ebpf_metadata_t;

int odp_action_to_bpf_action(const struct nlattr *, struct bpf_action *);
enum odp_key_fitness bpf_flow_key_to_flow(const struct bpf_flow_key *,
                                          struct flow *);
void bpf_flow_key_extract_metadata(const struct bpf_flow_key *,
                                   struct flow *flow);
void bpf_metadata_from_flow(const struct flow *flow,
                            struct ebpf_metadata_t *md);
enum odp_key_fitness odp_key_to_bpf_flow_key(const struct nlattr *, size_t,
                                             struct bpf_flow_key *,
                                             odp_port_t *in_port,
                                             bool verbose);
void bpf_flow_key_format(struct ds *ds, const struct bpf_flow_key *key);

#endif /* dpif-bpf-odp.h */
