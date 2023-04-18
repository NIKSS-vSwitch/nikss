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

#ifndef __NIKSS_BTF_H
#define __NIKSS_BTF_H

#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/btf.h>
#include <stdint.h>

#include <nikss/nikss.h>

const struct btf_type *btf_get_type_by_id(struct btf *btf, uint32_t type_id);

typedef struct btf_struct_member_md {
    const struct btf_member *member;
    int index;
    uint32_t effective_type_id;
    size_t bit_offset;
} btf_struct_member_md_t;

int btf_get_member_md_by_name(struct btf *btf, uint32_t type_id,
                              const char *member_name, btf_struct_member_md_t *md);
int btf_get_member_md_by_index(struct btf *btf, uint32_t type_id, uint16_t index,
                               btf_struct_member_md_t *md);

size_t btf_get_type_size_by_id(struct btf *btf, uint32_t type_id);

void init_btf(nikss_btf_t *btf);
int load_btf(nikss_context_t *nikss_ctx, nikss_btf_t *btf);
void free_btf(nikss_btf_t *btf);

int open_bpf_map(nikss_context_t *nikss_ctx, const char *name, nikss_btf_t *btf, nikss_bpf_map_descriptor_t *md);
int update_map_info(nikss_bpf_map_descriptor_t *md);

#endif  /* __NIKSS_BTF_H */
