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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <bpf/bpf.h>

#include <psabpf.h>
#include <psabpf_digest.h>

#include "btf.h"
#include "common.h"

void psabpf_digest_context_init(psabpf_digest_context_t *ctx)
{
    if (ctx == NULL)
        return;
    memset(ctx, 0, sizeof(psabpf_digest_context_t));

    ctx->queue.fd = -1;
    ctx->btf_metadata.associated_prog = -1;
}

void psabpf_digest_context_free(psabpf_digest_context_t *ctx)
{
    if (ctx == NULL)
        return;

    free_btf(&ctx->btf_metadata);
    close_object_fd(&(ctx->queue.fd));
    free_struct_field_descriptor_set(&ctx->fds);
}

static int parse_digest_btf(psabpf_digest_context_t *ctx)
{
    uint32_t type_id = psabtf_get_member_type_id_by_name(ctx->btf_metadata.btf, ctx->queue.btf_type_id, "value");
    return parse_struct_type(&ctx->btf_metadata, type_id, ctx->queue.value_size, &ctx->fds);
}

int psabpf_digest_name(psabpf_context_t *psabpf_ctx, psabpf_digest_context_t *ctx, const char *name)
{
    if (psabpf_ctx == NULL || ctx == NULL || name == NULL)
        return EINVAL;

    /* get the BTF, it is optional so print only warning */
    if (load_btf(psabpf_ctx, &ctx->btf_metadata) != NO_ERROR)
        fprintf(stderr, "warning: couldn't find BTF info\n");

    int ret = open_bpf_map(psabpf_ctx, name, &ctx->btf_metadata, &ctx->queue);
    if (ret != NO_ERROR)
        return ret;

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

int psabpf_digest_get_next(psabpf_digest_context_t *ctx, psabpf_digest_t *digest)
{
    if (ctx == NULL || digest == NULL)
        return EINVAL;

    memset(digest, 0, sizeof(psabpf_digest_t));

    if (ctx->queue.fd < 0)
        return EBADF;

    digest->raw_data = malloc(ctx->queue.value_size);
    if (digest->raw_data == NULL) {
        fprintf(stderr, "not enough memory\n");
        return ENOMEM;
    }

    int ret = bpf_map_lookup_and_delete_elem(ctx->queue.fd, NULL, digest->raw_data);
    if (ret != 0) {
        ret = errno;
        if (ret != ENOENT)
            fprintf(stderr, "failed to pop element from queue: %s\n", strerror(ret));
        psabpf_digest_free(digest);
        return ret;
    }

    return NO_ERROR;
}

void psabpf_digest_free(psabpf_digest_t *digest)
{
    if (digest == NULL)
        return;

    if (digest->raw_data != NULL)
        free(digest->raw_data);

    memset(digest, 0, sizeof(psabpf_digest_t));
}

psabpf_struct_field_t * psabpf_digest_get_next_field(psabpf_digest_context_t *ctx, psabpf_digest_t *digest)
{
    if (ctx == NULL || digest == NULL)
        return NULL;

    psabpf_struct_field_descriptor_t *fd;
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
