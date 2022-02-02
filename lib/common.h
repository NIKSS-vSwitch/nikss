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

#ifndef P4C_PSABPF_COMMON_H
#define P4C_PSABPF_COMMON_H

#include <stdint.h>
#include "../include/psabpf.h"

int str_ends_with(const char *str, const char *suffix);

/* Data len must be aligned to 4B */
void mem_bitwise_and(uint32_t *dst, uint32_t *mask, size_t len);

void close_object_fd(int *fd);

int build_ebpf_map_filename(char *buffer, size_t maxlen, psabpf_context_t *ctx, const char *name);
int build_ebpf_prog_filename(char *buffer, size_t maxlen, psabpf_context_t *ctx, const char *name);
int build_ebpf_pipeline_path(char *buffer, size_t maxlen, psabpf_context_t *ctx);

#endif  /* P4C_PSABPF_COMMON_H */
