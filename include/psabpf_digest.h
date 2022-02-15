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

#ifndef __PSABPF_DIGEST_H
#define __PSABPF_DIGEST_H

#include <psabpf.h>

typedef struct psabpf_digest_context {
    psabpf_bpf_map_descriptor_t queue;
    psabpf_btf_t btf_metadata;

    psabpf_struct_field_descriptor_set_t fds;
} psabpf_digest_context_t;

/* Used to read a next Digest message. */
typedef struct psabpf_digest {
    void *raw_data;  /* stores data from map as a single block */

    size_t current_field_id;
    psabpf_struct_field_t current;
} psabpf_digest_t;

void psabpf_digest_context_init(psabpf_digest_context_t *ctx);
void psabpf_digest_context_free(psabpf_digest_context_t *ctx);
int psabpf_digest_name(psabpf_context_t *psabpf_ctx, psabpf_digest_context_t *ctx, const char *name);
/* Will initialize digest, but must be later freed */
int psabpf_digest_get_next(psabpf_digest_context_t *ctx, psabpf_digest_t *digest);
void psabpf_digest_free(psabpf_digest_t *digest);

psabpf_struct_field_t * psabpf_digest_get_next_field(psabpf_digest_context_t *ctx, psabpf_digest_t *digest);

#endif  /* __PSABPF_DIGEST_H */
