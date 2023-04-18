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

#ifndef __NIKSS_TABLE_H
#define __NIKSS_TABLE_H

#include <nikss/nikss.h>

typedef struct nikss_bpf_map_descriptor nikss_bpf_map_descriptor_t;
int clear_table_cache(nikss_bpf_map_descriptor_t *map);

void move_action(nikss_action_t *dst, nikss_action_t *src);
int delete_all_map_entries(nikss_bpf_map_descriptor_t *map);
int construct_buffer(char * buffer, size_t buffer_len,
                     nikss_table_entry_ctx_t *ctx, nikss_table_entry_t *entry,
                     int (*btf_info_func)(char *, nikss_table_entry_ctx_t *, nikss_table_entry_t *),
                     int (*byte_by_byte_func)(char *, nikss_table_entry_ctx_t *, nikss_table_entry_t *));
int fill_key_btf_info(char * buffer, nikss_table_entry_ctx_t *ctx, nikss_table_entry_t *entry);
int fill_key_byte_by_byte(char * buffer, nikss_table_entry_ctx_t *ctx, nikss_table_entry_t *entry);
int parse_table_key(nikss_table_entry_ctx_t *ctx, nikss_table_entry_t *entry,
                    const char *key, const char *key_mask);
int open_ternary_table(nikss_context_t *nikss_ctx, nikss_table_entry_ctx_t *ctx, const char *name);
int nikss_table_entry_goto_next_key(nikss_table_entry_ctx_t *ctx);

#endif  /* __NIKSS_TABLE_H */
