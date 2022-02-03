/*
 * Copyright 2022 Orange
 * Copyright 2022 Warsaw University of Technology
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __PSABPF_BTF_H
#define __PSABPF_BTF_H

#include <stdint.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <linux/btf.h>

const struct btf_type * psabtf_get_type_by_id(struct btf * btf, uint32_t type_id);

uint32_t psabtf_get_type_id_by_name(struct btf * btf, const char * name);

typedef struct psabtf_struct_member_md {
    const struct btf_member * member;
    int index;
    uint32_t effective_type_id;
    size_t bit_offset;
} psabtf_struct_member_md_t;

int psabtf_get_member_md_by_name(struct btf * btf, uint32_t type_id,
        const char * member_name, psabtf_struct_member_md_t * md);
int psabtf_get_member_md_by_index(struct btf * btf, uint32_t type_id, uint16_t index,
        psabtf_struct_member_md_t * md);
uint32_t psabtf_get_member_type_id_by_name(struct btf * btf, uint32_t type_id,
        const char * member_name);

size_t psabtf_get_type_size_by_id(struct btf * btf, uint32_t type_id);

int load_btf(psabpf_context_t *psabpf_ctx, psabpf_btf_t *btf);
void free_btf(psabpf_btf_t *btf);

int open_bpf_map(psabpf_context_t *psabpf_ctx, const char *name, psabpf_btf_t *btf, psabpf_bpf_map_descriptor_t *md);

#endif  // __PSABPF_BTF_H
