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

#ifndef __PSABPF_VALUE_SET_H_
#define __PSABPF_VALUE_SET_H_

#include <psabpf.h>

typedef struct psabpf_value_set_context {
    psabpf_bpf_map_descriptor_t set_map;
    psabpf_bpf_map_descriptor_t prefixes;
    psabpf_bpf_map_descriptor_t tuple_map;
    psabpf_btf_t btf_metadata;
    psabpf_struct_field_descriptor_set_t fds;

    void *current_raw_key;
    void *current_raw_key_mask;
} psabpf_value_set_context_t;

void psabpf_value_set_context_init(psabpf_value_set_context_t *ctx);
void psabpf_value_set_context_free(psabpf_value_set_context_t *ctx);
int psabpf_value_set_context_name(psabpf_context_t *psabpf_ctx, psabpf_value_set_context_t *ctx, const char *name);
psabpf_table_entry_t *psabpf_value_set_get_next_entry(psabpf_value_set_context_t *ctx);

int psabpf_value_set_insert(psabpf_value_set_context_t *ctx, psabpf_table_entry_t *entry);
int psabpf_value_set_delete(psabpf_value_set_context_t *ctx, psabpf_table_entry_t *entry);

#endif /* __PSABPF_VALUE_SET_H_ */
