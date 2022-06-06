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
#include <stdlib.h>
#include <errno.h>
#include <bpf/bpf.h>

#include <psabpf.h>
#include <psabpf_value_set.h>
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

void psabpf_value_set_init(psabpf_value_set_t *value) {
    if (value == NULL)
        return;

    memset(value, 0, sizeof(psabpf_value_set_t));
}

void psabpf_value_set_free(psabpf_value_set_t *value) {
    if (value == NULL)
        return;

    free_struct_field_set(&value->value);

    if (value->raw_data != NULL)
        free(value->raw_data);
    value->raw_data = NULL;
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
        fprintf(stderr, "%s: couldn't get key BTF info of a value_set instance\n", name);
        return EOPNOTSUPP;
    }

    return NO_ERROR;
}

int psabpf_value_set_set_value(psabpf_value_set_t *value, const void *data, size_t data_len) {
    if (value == NULL)
        return EINVAL;
    if (data == NULL || data_len < 1)
        return ENODATA;

    int ret = struct_field_set_append(&value->value, data, data_len);
    if (ret != NO_ERROR)
        fprintf(stderr, "couldn't append value to an entry: %s\n", strerror(ret));
    return ret;
}

psabpf_struct_field_t * psabpf_value_set_get_next_value_field(psabpf_value_set_context_t *ctx, psabpf_value_set_t *entry) {
    if (ctx == NULL || entry == NULL)
        return NULL;

    psabpf_struct_field_descriptor_t *fd;
    fd = get_struct_field_descriptor(&ctx->fds, entry->current_field_id);
    if (fd == NULL) {
        entry->current_field_id = 0;
        return NULL;
    }

    entry->current.type = fd->type;
    entry->current.data_len = fd->data_len;
    entry->current.name = fd->name;
    entry->current.data = entry->raw_data + fd->data_offset;

    entry->current_field_id = entry->current_field_id + 1;

    return &entry->current;
}

static void *allocate_value_buffer(psabpf_value_set_context_t *ctx, psabpf_value_set_t *value)
{
    if (value->raw_data != NULL)
        return value->raw_data;  /* already allocated */

    value->raw_data = malloc(ctx->set_map.key_size);
    if (value->raw_data == NULL)
        fprintf(stderr, "not enough memory\n");

    return value->raw_data;
}

psabpf_value_set_t * psabpf_value_set_get_next(psabpf_value_set_context_t *ctx)
{
    if (ctx == NULL)
        return NULL;

    if (allocate_value_buffer(ctx, &ctx->current_value) == NULL)
        return NULL;

    /* on first call ctx->prev_entry_ke must be NULL */
    if (bpf_map_get_next_key(ctx->set_map.fd, ctx->prev_entry_key, ctx->current_value.raw_data) != 0) {
        /* no more entries, prepare for next iteration */
        if (ctx->prev_entry_key != NULL)
            free(ctx->prev_entry_key);
        ctx->prev_entry_key = NULL;

        return NULL;
    }

    if (ctx->prev_entry_key == NULL) {
        ctx->prev_entry_key = malloc(ctx->set_map.key_size);
        if (ctx->prev_entry_key == NULL) {
            fprintf(stderr, "not enough memory\n");
            return NULL;
        }
    }

    memcpy(ctx->prev_entry_key, ctx->current_value.raw_data, ctx->set_map.key_size);

    return &ctx->current_value;
}

int psabpf_value_set_insert(psabpf_value_set_context_t *ctx, psabpf_value_set_t *value) {
    if (allocate_value_buffer(ctx, value) == NULL)
        return ENOMEM;

    int ret = construct_struct_from_fields(&value->value, &ctx->fds, value->raw_data, ctx->set_map.key_size);
    if (ret != NO_ERROR)
        return ret;

    void *empty_value = calloc(1, ctx->set_map.value_size);
    ret = bpf_map_update_elem(ctx->set_map.fd, value->raw_data, empty_value, 0);
    if (ret != NO_ERROR) {
        fprintf(stderr, "failed to insert a value to a value_set: %s\n", strerror(ret));
        return ret;
    }

    return NO_ERROR;
}

int psabpf_value_set_delete(psabpf_value_set_context_t *ctx, psabpf_value_set_t *value) {
    if (allocate_value_buffer(ctx, value) == NULL)
        return ENOMEM;

    int ret = construct_struct_from_fields(&value->value, &ctx->fds, value->raw_data, ctx->set_map.key_size);
    if (ret != NO_ERROR)
        return ret;

    ret = bpf_map_delete_elem(ctx->set_map.fd, value->raw_data);
    if (ret != NO_ERROR) {
        fprintf(stderr, "failed to delete an element from a value_set: %s\n", strerror(ret));
        return ret;
    }

    return NO_ERROR;
}
