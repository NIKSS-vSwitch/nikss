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
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nikss.h>
#include <nikss_value_set.h>

#include "btf.h"
#include "common.h"
#include "nikss_table.h"

void nikss_value_set_context_init(nikss_value_set_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    memset(ctx, 0, sizeof(nikss_value_set_context_t));
    init_btf(&ctx->btf_metadata);
}

void nikss_value_set_context_free(nikss_value_set_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->current_raw_key != NULL) {
        free(ctx->current_raw_key);
    }
    ctx->current_raw_key = NULL;

    if (ctx->current_raw_key_mask != NULL) {
        free(ctx->current_raw_key_mask);
    }
    ctx->current_raw_key_mask = NULL;

    free_btf(&ctx->btf_metadata);
    close_object_fd(&(ctx->set_map.fd));
    free_struct_field_descriptor_set(&ctx->fds);
}

static int parse_key_type(nikss_value_set_context_t *ctx)
{
    return parse_struct_type(&ctx->btf_metadata, ctx->set_map.key_type_id, ctx->set_map.key_size, &ctx->fds);
}

int nikss_value_set_context_name(nikss_context_t *nikss_ctx, nikss_value_set_context_t *ctx, const char *name)
{
    if (nikss_ctx == NULL || ctx == NULL || name == NULL) {
        return EINVAL;
    }

    if (load_btf(nikss_ctx, &ctx->btf_metadata) != NO_ERROR) {
        fprintf(stderr, "couldn't find a BTF info\n");
    }

    int ret = open_bpf_map(nikss_ctx, name, &ctx->btf_metadata, &ctx->set_map);
    /* if map does not exist, try the ternary table */
    if (ret == ENOENT) {
        nikss_table_entry_ctx_t tbl_entry_ctx;
        nikss_table_entry_ctx_init(&tbl_entry_ctx);
        ret = open_ternary_table(nikss_ctx, &tbl_entry_ctx, name);

        if (ret != NO_ERROR) {
            fprintf(stderr, "couldn't open a value_set %s\n", name);
            nikss_table_entry_ctx_free(&tbl_entry_ctx);
            return ret;
        }

        ctx->prefixes = tbl_entry_ctx.prefixes;
        ctx->tuple_map = tbl_entry_ctx.tuple_map;

        nikss_table_entry_ctx_free(&tbl_entry_ctx);
    }


    if (parse_key_type(ctx) != NO_ERROR) {
        fprintf(stderr, "%s: couldn't parse structure of a value_set instance\n", name);
        return EOPNOTSUPP;
    }

    return NO_ERROR;
}

nikss_table_entry_t *nikss_value_set_get_next_entry(nikss_value_set_context_t *ctx)
{
    nikss_table_entry_t * new_entry = NULL;
    nikss_table_entry_ctx_t tec = {
            .table = ctx->set_map,
            .btf_metadata = ctx->btf_metadata,
    };

    /* Copy current keys from value_set_ctx to table_entry_ctx */
    if (ctx->current_raw_key != NULL) {
        tec.current_raw_key = malloc(ctx->set_map.key_size);
        tec.current_raw_key_mask = malloc(ctx->prefixes.key_size);
        memcpy(tec.current_raw_key, ctx->current_raw_key, ctx->set_map.key_size);
        memcpy(tec.current_raw_key_mask, ctx->current_raw_key_mask, ctx->prefixes.key_size);
    }

    if (nikss_table_entry_goto_next_key(&tec) != NO_ERROR) {
        /* nikss_table_entry_get_next_key free'ed a memory before */
        ctx->current_raw_key = NULL;
        ctx->current_raw_key_mask = NULL;
        goto clean_up;
    }

    /* Copy current keys from table_entry_ctx to value_set_ctx */
    if (ctx->current_raw_key != NULL) {
        free(ctx->current_raw_key);
    }
    ctx->current_raw_key = malloc(ctx->set_map.key_size);
    memcpy(ctx->current_raw_key, tec.current_raw_key, ctx->set_map.key_size);

    if (ctx->current_raw_key_mask != NULL) {
        free(ctx->current_raw_key_mask);
    }
    ctx->current_raw_key_mask = malloc(tec.prefixes.key_size);
    memcpy(ctx->current_raw_key_mask, tec.current_raw_key_mask, tec.prefixes.key_size);

    new_entry = malloc(sizeof(nikss_table_entry_t));
    nikss_table_entry_init(new_entry);

    int return_code = parse_table_key(&tec, new_entry, tec.current_raw_key, tec.current_raw_key_mask);
    if (return_code != NO_ERROR) {
        fprintf(stderr, "failed to parse entry: %s\n", strerror(return_code));
        goto clean_up;
    }

clean_up:
    nikss_table_entry_ctx_free(&tec);

    return new_entry;
}

int nikss_value_set_insert(nikss_value_set_context_t *ctx, nikss_table_entry_t *entry)
{
    char *key_buffer = NULL;
    char *value_buffer = NULL;
    int return_code = NO_ERROR;

    if (ctx == NULL || entry == NULL) {
        return EINVAL;
    }

    /* prepare buffers for map key/value */
    key_buffer = malloc(ctx->set_map.key_size);
    value_buffer = calloc(1, ctx->set_map.value_size);
    if (key_buffer == NULL || value_buffer == NULL) {
        fprintf(stderr, "not enough memory\n");
        return_code = ENOMEM;
        goto clean_up;
    }

    nikss_table_entry_ctx_t tec = {
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
    if (ctx->set_map.type == BPF_MAP_TYPE_ARRAY) {
        bpf_flags = BPF_ANY;
    }
    return_code = bpf_map_update_elem(ctx->set_map.fd, key_buffer, value_buffer, bpf_flags);
    if (return_code != 0) {
        return_code = errno;
        fprintf(stderr, "failed to set up entry: %s\n", strerror(errno));
    }

clean_up:
    if (key_buffer != NULL) {
        free(key_buffer);
    }
    if (value_buffer != NULL) {
        free(value_buffer);
    }

    return return_code;
}

int nikss_value_set_delete(nikss_value_set_context_t *ctx, nikss_table_entry_t *entry)
{
    nikss_table_entry_ctx_t tec = {
            .table = ctx->set_map,
            .btf_metadata = ctx->btf_metadata,
            .cache.fd = -1,
    };

    int ret = nikss_table_entry_del(&tec, entry);

    return ret;
}
