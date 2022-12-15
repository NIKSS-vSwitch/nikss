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

#include <bpf/bpf.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <nikss.h>
#include <nikss_digest.h>

#include "btf.h"
#include "common.h"

void nikss_digest_ctx_init(nikss_digest_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    memset(ctx, 0, sizeof(nikss_digest_context_t));

    ctx->queue.fd = -1;
    init_btf(&ctx->btf_metadata);
}

void nikss_digest_ctx_free(nikss_digest_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    free_btf(&ctx->btf_metadata);
    close_object_fd(&(ctx->queue.fd));
    free_struct_field_descriptor_set(&ctx->fds);
}

static int parse_digest_btf(nikss_digest_context_t *ctx)
{
    return parse_struct_type(&ctx->btf_metadata, ctx->queue.value_type_id, ctx->queue.value_size, &ctx->fds);
}

int nikss_digest_ctx_name(nikss_context_t *nikss_ctx, nikss_digest_context_t *ctx, const char *name)
{
    if (nikss_ctx == NULL || ctx == NULL || name == NULL) {
        return EINVAL;
    }

    /* get the BTF, it is optional so print only warning */
    if (load_btf(nikss_ctx, &ctx->btf_metadata) != NO_ERROR) {
        fprintf(stderr, "warning: couldn't find BTF info\n");
    }

    int ret = open_bpf_map(nikss_ctx, name, &ctx->btf_metadata, &ctx->queue);
    if (ret != NO_ERROR) {
        return ret;
    }

    if (ctx->queue.type != BPF_MAP_TYPE_QUEUE) {
        fprintf(stderr, "%s: not a Digest instance\n", name);
        close_object_fd(&ctx->queue.fd);
        return EOPNOTSUPP;
    }

    ret = parse_digest_btf(ctx);
    if (ret != NO_ERROR) {
        fprintf(stderr, "failed to obtain fields names\n");
        return ret;
    }

    return NO_ERROR;
}

int nikss_digest_get_next(nikss_digest_context_t *ctx, nikss_digest_t *digest)
{
    if (ctx == NULL || digest == NULL) {
        return EINVAL;
    }

    memset(digest, 0, sizeof(nikss_digest_t));

    if (ctx->queue.fd < 0) {
        return EBADF;
    }

    digest->raw_data = malloc(ctx->queue.value_size);
    if (digest->raw_data == NULL) {
        fprintf(stderr, "not enough memory\n");
        return ENOMEM;
    }

    int ret = bpf_map_lookup_and_delete_elem(ctx->queue.fd, NULL, digest->raw_data);
    if (ret != 0) {
        ret = errno;
        if (ret != ENOENT) {
            fprintf(stderr, "failed to pop element from queue: %s\n", strerror(ret));
        }
        nikss_digest_free(digest);
        return ret;
    }

    fix_struct_data_byte_order(&ctx->fds, digest->raw_data, ctx->queue.value_size);

    return NO_ERROR;
}

void nikss_digest_free(nikss_digest_t *digest)
{
    if (digest == NULL) {
        return;
    }

    if (digest->raw_data != NULL) {
        free(digest->raw_data);
    }

    memset(digest, 0, sizeof(nikss_digest_t));
}

nikss_struct_field_t * nikss_digest_get_next_field(nikss_digest_context_t *ctx, nikss_digest_t *digest)
{
    if (ctx == NULL || digest == NULL) {
        return NULL;
    }

    nikss_struct_field_descriptor_t *fd = NULL;
    fd = get_struct_field_descriptor(&ctx->fds, digest->current_field_id);
    if (fd == NULL) {
        digest->current_field_id = 0;
        return NULL;
    }

    digest->current.type = fd->type;
    digest->current.data_len = fd->data_len;
    digest->current.name = fd->name;
    digest->current.data = digest->raw_data + fd->data_offset;

    digest->current_field_id = digest->current_field_id + 1;

    return &digest->current;
}
