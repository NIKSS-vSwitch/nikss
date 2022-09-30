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

#ifndef P4C_PSABPF_TABLE_H
#define P4C_PSABPF_TABLE_H

#include "psabpf.h"

typedef struct psabpf_bpf_map_descriptor psabpf_bpf_map_descriptor_t;
int clear_table_cache(psabpf_bpf_map_descriptor_t *map);

void move_action(psabpf_action_t *dst, psabpf_action_t *src);
int delete_all_map_entries(psabpf_bpf_map_descriptor_t *map);
int construct_buffer(char * buffer, size_t buffer_len,
                     psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry,
                     int (*btf_info_func)(char *, psabpf_table_entry_ctx_t *, psabpf_table_entry_t *),
                     int (*byte_by_byte_func)(char *, psabpf_table_entry_ctx_t *, psabpf_table_entry_t *));
int fill_key_btf_info(char * buffer, psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry);
int fill_key_byte_by_byte(char * buffer, psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry);
int parse_table_key(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry,
                    const char *key, const char *key_mask);
int open_ternary_table(psabpf_context_t *psabpf_ctx, psabpf_table_entry_ctx_t *ctx, const char *name);
int psabpf_table_entry_goto_next_key(psabpf_table_entry_ctx_t *ctx);

#endif  /* P4C_PSABPF_TABLE_H */
