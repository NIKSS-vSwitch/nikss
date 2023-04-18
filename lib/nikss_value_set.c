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

#include <nikss/nikss.h>
#include <nikss/nikss_value_set.h>

#include "btf.h"
#include "common.h"
#include "nikss_table.h"

void nikss_value_set_context_init(nikss_value_set_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    memset(ctx, 0, sizeof(nikss_value_set_context_t));

    ctx->is_ternary_match = false;

    init_btf(&ctx->btf_metadata);
    ctx->set_map.fd = -1;
    ctx->prefixes.fd = -1;
    ctx->tuple_map.fd = -1;
    ctx->cache.fd = -1;

    nikss_table_entry_init(&ctx->current_entry);
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
    close_object_fd(&(ctx->prefixes.fd));
    close_object_fd(&(ctx->tuple_map.fd));
    close_object_fd(&(ctx->cache.fd));

    nikss_table_entry_free(&ctx->current_entry);
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

        ctx->is_ternary_match = true;
        ctx->prefixes = tbl_entry_ctx.prefixes;
        ctx->tuple_map = tbl_entry_ctx.tuple_map;
        /* Invalidate file descriptors in tec, so they will not be closed during clean up. */
        tbl_entry_ctx.prefixes.fd = -1;
        tbl_entry_ctx.tuple_map.fd = -1;

        nikss_table_entry_ctx_free(&tbl_entry_ctx);
    }

    /* open cache table, this is optional feature for value_sets */
    char map_name[256];
    snprintf(map_name, sizeof(map_name), "%s_cache", name);
    ret = open_bpf_map(nikss_ctx, map_name, &ctx->btf_metadata, &ctx->cache);
    if (ret == NO_ERROR) {
        fprintf(stderr, "found cache for value_set: %s\n", name);
    }

    return NO_ERROR;
}

nikss_table_entry_t *nikss_value_set_get_next_entry(nikss_value_set_context_t *ctx)
{
    nikss_table_entry_t * new_entry = NULL;
    nikss_table_entry_ctx_t tec = {
            .table = ctx->set_map,
            .prefixes = ctx->prefixes,
            .tuple_map = ctx->tuple_map,
            .btf_metadata = ctx->btf_metadata,
            .current_raw_key = ctx->current_raw_key,
            .current_raw_key_mask = ctx->current_raw_key_mask,
            .is_ternary = ctx->is_ternary_match,
    };

    if (nikss_table_entry_goto_next_key(&tec) != NO_ERROR) {
        goto clean_up;
    }

    nikss_table_entry_free(&ctx->current_entry);
    nikss_table_entry_init(&ctx->current_entry);

    int return_code = parse_table_key(&tec, &ctx->current_entry, tec.current_raw_key, tec.current_raw_key_mask);
    if (return_code != NO_ERROR) {
        fprintf(stderr, "failed to parse entry: %s\n", strerror(return_code));
        nikss_table_entry_free(&ctx->current_entry);
        goto clean_up;
    }

    new_entry = &ctx->current_entry;

clean_up:
    /* Resources were managed by table entry context, now move back what we need to PVS! */
    ctx->set_map.fd = tec.table.fd;  /* might be changed for ternary match */
    ctx->current_raw_key = tec.current_raw_key;
    ctx->current_raw_key_mask = tec.current_raw_key_mask;

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
            .cache = ctx->cache,
            .is_ternary = ctx->is_ternary_match,
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
            .prefixes = ctx->prefixes,
            .tuple_map = ctx->tuple_map,
            .cache = ctx->cache,
            .btf_metadata = ctx->btf_metadata,
            .is_ternary = ctx->is_ternary_match,
    };

    int ret = nikss_table_entry_del(&tec, entry);

    return ret;
}
