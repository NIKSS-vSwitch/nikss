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

#include <string.h>
#include <errno.h>

#include <psabpf.h>
#include "common.h"
#include "btf.h"

void psabpf_counter_ctx_init(psabpf_counter_context_t *ctx)
{
    if (ctx == NULL)
        return;

    memset(ctx, 0, sizeof(psabpf_counter_context_t));
    ctx->counter.fd = -1;
    ctx->btf_metadata.associated_prog = -1;
}

void psabpf_counter_ctx_free(psabpf_counter_context_t *ctx)
{
    if (ctx == NULL)
        return;

    free_btf(&ctx->btf_metadata);
    close_object_fd(&(ctx->counter.fd));
}

int psabpf_counter_open(psabpf_context_t *psabpf_ctx, psabpf_counter_context_t *ctx, const char *name)
{
    if (psabpf_ctx == NULL || ctx == NULL || name == NULL)
        return EINVAL;

    /* get the BTF, it is optional so print only warning */
    if (load_btf(psabpf_ctx, &ctx->btf_metadata) != NO_ERROR)
        fprintf(stderr, "warning: couldn't find BTF info\n");

    int ret = open_bpf_map(psabpf_ctx, name, &ctx->btf_metadata, &ctx->counter);
    if (ret != NO_ERROR)
        return ret;

    return NO_ERROR;
}

