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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>

#include <psabpf.h>
#include <psabpf_value_set.h>
#include "psabpf_table.h"
#include "common.h"
#include "btf.h"

void psabpf_value_set_context_init(psabpf_value_set_context_t *ctx) {
    if (ctx == NULL)
        return;

    memset(ctx, 0, sizeof(psabpf_value_set_context_t));
}

void psabpf_value_set_context_free(psabpf_value_set_context_t *ctx) {
    if (ctx == NULL)
        return;

    free_btf(&ctx->btf_metadata);
    close_object_fd(&(ctx->set_map.fd));
    free_struct_field_descriptor_set(&ctx->fds);
}

static int parse_key_type(psabpf_value_set_context_t *ctx)
{
    uint32_t type_id = psabtf_get_member_type_id_by_name(ctx->btf_metadata.btf, ctx->set_map.btf_type_id, "key");

    return parse_struct_type(&ctx->btf_metadata, type_id, ctx->set_map.key_size, &ctx->fds);
}

int psabpf_value_set_context_name(psabpf_context_t *psabpf_ctx, psabpf_value_set_context_t *ctx, const char *name) {
    if (psabpf_ctx == NULL || ctx == NULL || name == NULL)
        return EINVAL;

    if (load_btf(psabpf_ctx, &ctx->btf_metadata) != NO_ERROR) {
        fprintf(stderr, "couldn't find a BTF info\n");
    }

    int ret = open_bpf_map(psabpf_ctx, name, &ctx->btf_metadata, &ctx->set_map);
    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't open a value_set %s\n", name);
        return ret;
    }

    if (parse_key_type(ctx) != NO_ERROR) {
        fprintf(stderr, "%s: couldn't parse structure of a value_set instance\n", name);
        return EOPNOTSUPP;
    }

    return NO_ERROR;
}

int psabpf_value_set_insert(psabpf_value_set_context_t *ctx, psabpf_table_entry_t *entry) {
    char *key_buffer = NULL;
    char *value_buffer = NULL;
    int return_code = NO_ERROR;

    if (ctx == NULL || entry == NULL)
        return EINVAL;

    /* prepare buffers for map key/value */
    key_buffer = malloc(ctx->set_map.key_size);
    value_buffer = calloc(1, ctx->set_map.value_size);
    if (key_buffer == NULL || value_buffer == NULL) {
        fprintf(stderr, "not enough memory\n");
        return_code = ENOMEM;
        goto clean_up;
    }

    psabpf_table_entry_ctx_t tec = {
            .table = ctx->set_map,
            .btf_metadata = ctx->btf_metadata,
            .cache.fd = -1,
    };
    return_code = construct_buffer(key_buffer, ctx->set_map.key_size, &tec, entry,
                                   fill_key_btf_info, fill_key_byte_by_byte);
    if (return_code != NO_ERROR) {
        fprintf(stderr, "failed to construct key\n");
        goto clean_up;
    }

    /* update map */
    uint64_t bpf_flags = BPF_NOEXIST;
    if (ctx->set_map.type == BPF_MAP_TYPE_ARRAY)
        bpf_flags = BPF_ANY;
    return_code = bpf_map_update_elem(ctx->set_map.fd, key_buffer, value_buffer, bpf_flags);
    if (return_code != 0) {
        return_code = errno;
        fprintf(stderr, "failed to set up entry: %s\n", strerror(errno));
    }

clean_up:
    if (key_buffer != NULL)
        free(key_buffer);
    if (value_buffer != NULL)
        free(value_buffer);

    return return_code;
}

int psabpf_value_set_delete(psabpf_value_set_context_t *ctx, psabpf_table_entry_t *entry) {

    psabpf_table_entry_ctx_t tec = {
            .table = ctx->set_map,
            .btf_metadata = ctx->btf_metadata,
            .cache.fd = -1,
    };

    int ret = psabpf_table_entry_del(&tec, entry);

    return ret;
}
