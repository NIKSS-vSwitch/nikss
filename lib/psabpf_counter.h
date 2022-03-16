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

#ifndef P4C_PSABPF_COUNTER_H
#define P4C_PSABPF_COUNTER_H

#include <psabpf.h>

/* Might be used to test whether given type ID is a valid counter */
psabpf_counter_type_t get_counter_type(psabpf_btf_t *btf, uint32_t type_id);

int convert_counter_entry_to_data(psabpf_counter_context_t *ctx, psabpf_counter_entry_t *entry, uint8_t *buffer);
int convert_counter_data_to_entry(const uint8_t *data, size_t counter_size,
                                  psabpf_counter_type_t counter_type, psabpf_counter_entry_t *entry);

#endif  /* P4C_PSABPF_COUNTER_H */
