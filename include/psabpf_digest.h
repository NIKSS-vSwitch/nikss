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

#ifndef __NIKSS_DIGEST_H
#define __NIKSS_DIGEST_H

#include <psabpf.h>

typedef struct nikss_digest_context {
    nikss_bpf_map_descriptor_t queue;
    nikss_btf_t btf_metadata;

    nikss_struct_field_descriptor_set_t fds;
} nikss_digest_context_t;

/* Used to read a next Digest message. */
typedef struct nikss_digest {
    char *raw_data;  /* stores data from map as a single block */

    size_t current_field_id;
    nikss_struct_field_t current;
} nikss_digest_t;

void nikss_digest_ctx_init(nikss_digest_context_t *ctx);
void nikss_digest_ctx_free(nikss_digest_context_t *ctx);
int nikss_digest_ctx_name(nikss_context_t *nikss_ctx, nikss_digest_context_t *ctx, const char *name);
/* Will initialize digest, but must be later freed */
int nikss_digest_get_next(nikss_digest_context_t *ctx, nikss_digest_t *digest);
void nikss_digest_free(nikss_digest_t *digest);

nikss_struct_field_t * nikss_digest_get_next_field(nikss_digest_context_t *ctx, nikss_digest_t *digest);

#endif  /* __NIKSS_DIGEST_H */
