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
#include "bpf_defs.h"

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
    free_struct_field_descriptor_set(&ctx->key_fds);
}

static int parse_counter_value(psabpf_counter_context_t *ctx)
{
    uint32_t value_type_id;
    value_type_id = psabtf_get_member_type_id_by_name(ctx->btf_metadata.btf, ctx->counter.btf_type_id, "value");

    const struct btf_type *value_type = psabtf_get_type_by_id(ctx->btf_metadata.btf, value_type_id);
    if (btf_kind(value_type) != BTF_KIND_STRUCT)
        return EINVAL;

    unsigned value_entries = btf_vlen(value_type);
    if (value_entries != COUNTER_PACKETS_OR_BYTES_STRUCT_ENTRIES &&
        value_entries != COUNTER_PACKETS_AND_BYTES_STRUCT_ENTRIES)
        return EINVAL;

    /* Allowed field names: "packets", "bytes" */
    bool has_bytes = false;
    bool has_packets = false;
    const struct btf_member *m = btf_members(value_type);
    for (unsigned i = 0; i < value_entries; i++, m++) {
        const char *field_name = btf__name_by_offset(ctx->btf_metadata.btf, m->name_off);
        if (field_name == NULL)
            return false;

        if (strcmp(field_name, "bytes") == 0)
            has_bytes = true;
        else if (strcmp(field_name, "packets") == 0)
            has_packets = true;
        else
            return EINVAL;
    }

    /* Decode counter type */
    if (has_bytes == true && has_packets == true)
        ctx->counter_type = PSABPF_COUNTER_TYPE_BYTES_AND_PACKETS;
    else if (has_bytes == true && has_packets == false)
        ctx->counter_type = PSABPF_COUNTER_TYPE_BYTES;
    else if (has_bytes == false && has_packets == true)
        ctx->counter_type = PSABPF_COUNTER_TYPE_PACKETS;
    else
        return EINVAL;

    /* Validate counter size - up to 64 bits per counter*/
    if ((ctx->counter_type == PSABPF_COUNTER_TYPE_BYTES_AND_PACKETS && ctx->counter.value_size > 16) ||
        (ctx->counter_type != PSABPF_COUNTER_TYPE_BYTES_AND_PACKETS && ctx->counter.value_size > 8))
        return ENOTSUP;

    return NO_ERROR;
}

static int parse_counter_key(psabpf_counter_context_t *ctx)
{
    uint32_t type_id = psabtf_get_member_type_id_by_name(ctx->btf_metadata.btf, ctx->counter.btf_type_id, "key");
    return parse_struct_type(&ctx->btf_metadata, type_id, ctx->counter.key_size, &ctx->key_fds);
}

int psabpf_counter_open(psabpf_context_t *psabpf_ctx, psabpf_counter_context_t *ctx, const char *name)
{
    if (psabpf_ctx == NULL || ctx == NULL || name == NULL)
        return EINVAL;

    /* get the BTF, will not work without it because there is too many possible configurations */
    if (load_btf(psabpf_ctx, &ctx->btf_metadata) != NO_ERROR) {
        fprintf(stderr, "couldn't find BTF info\n");
        return ENOTSUP;
    }

    int ret = open_bpf_map(psabpf_ctx, name, &ctx->btf_metadata, &ctx->counter);
    if (ret != NO_ERROR)
        return ret;

    if (parse_counter_value(ctx) != NO_ERROR) {
        fprintf(stderr, "%s: not a Counter instance\n", name);
        close_object_fd(&ctx->counter.fd);
        return EOPNOTSUPP;
    }

    return parse_counter_key(ctx);
}

