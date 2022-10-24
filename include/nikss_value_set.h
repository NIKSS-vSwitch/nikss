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

#ifndef __NIKSS_VALUE_SET_H_
#define __NIKSS_VALUE_SET_H_

#include <nikss.h>

typedef struct nikss_value_set_context {
    nikss_bpf_map_descriptor_t set_map;
    nikss_bpf_map_descriptor_t prefixes;
    nikss_bpf_map_descriptor_t tuple_map;
    nikss_bpf_map_descriptor_t cache;

    nikss_btf_t btf_metadata;

    bool is_ternary_match;

    void *current_raw_key;
    void *current_raw_key_mask;
    nikss_table_entry_t current_entry;
} nikss_value_set_context_t;

void nikss_value_set_context_init(nikss_value_set_context_t *ctx);
void nikss_value_set_context_free(nikss_value_set_context_t *ctx);
int nikss_value_set_context_name(nikss_context_t *nikss_ctx, nikss_value_set_context_t *ctx, const char *name);
nikss_table_entry_t *nikss_value_set_get_next_entry(nikss_value_set_context_t *ctx);

int nikss_value_set_insert(nikss_value_set_context_t *ctx, nikss_table_entry_t *entry);
int nikss_value_set_delete(nikss_value_set_context_t *ctx, nikss_table_entry_t *entry);

#endif /* __NIKSS_VALUE_SET_H_ */
