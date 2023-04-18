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

#ifndef __NIKSS_COMMON_H
#define __NIKSS_COMMON_H

#include <stdint.h>
#include <nikss/nikss.h>

int str_ends_with(const char *str, const char *suffix);
bool remove_suffix_from_str(char *str, const char *suffix);

/* Data len must be aligned to 4B */
void mem_bitwise_and(uint32_t *dst, uint32_t *mask, size_t len);
void swap_byte_order(char *data, size_t len);

void close_object_fd(int *fd);

int build_ebpf_map_filename(char *buffer, size_t maxlen, nikss_context_t *ctx, const char *name);
int build_ebpf_prog_filename(char *buffer, size_t maxlen, nikss_context_t *ctx, const char *name);
int build_ebpf_pipeline_path(char *buffer, size_t maxlen, nikss_context_t *ctx);

void free_struct_field_descriptor_set(nikss_struct_field_descriptor_set_t *fds);
int parse_struct_type(nikss_btf_t *btf_md, uint32_t type_id, size_t data_size, nikss_struct_field_descriptor_set_t *fds);
nikss_struct_field_descriptor_t *get_struct_field_descriptor(nikss_struct_field_descriptor_set_t *fds, size_t index);

void free_struct_field_set(nikss_struct_field_set_t *sfs);
int struct_field_set_append(nikss_struct_field_set_t *sfs, const void *data, size_t data_len);
int construct_struct_from_fields(nikss_struct_field_set_t *data, nikss_struct_field_descriptor_set_t *fds,
                                 char *buffer, size_t buffer_len);

/* Will swap byte order of fields if required in buffer */
void fix_struct_data_byte_order(nikss_struct_field_descriptor_set_t *fds, char *buffer, size_t buffer_len);

#endif  /* __NIKSS_COMMON_H */
