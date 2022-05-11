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
#include "common.h"
#include "btf.h"
#include "bpf_defs.h"

void psabpf_register_ctx_init(psabpf_register_context_t *ctx) {
    if (ctx == NULL)
        return;

    memset(ctx, 0, sizeof(psabpf_register_context_t));
}

void psabpf_register_ctx_free(psabpf_register_context_t *ctx) {
    if (ctx == NULL)
        return;

    free_btf(&ctx->btf_metadata);
    close_object_fd(&(ctx->reg.fd));
    free_struct_field_descriptor_set(&ctx->key_fds);
    free_struct_field_descriptor_set(&ctx->value_fds);
}

static int parse_key_type(psabpf_register_context_t *ctx)
{
    uint32_t type_id = 0;
    if (ctx->btf_metadata.btf != NULL) {
        type_id = psabtf_get_member_type_id_by_name(ctx->btf_metadata.btf, ctx->reg.btf_type_id, "key");
    }

    return parse_struct_type(&ctx->btf_metadata, type_id, ctx->reg.key_size, &ctx->key_fds);
}

static int parse_value_type(psabpf_register_context_t *ctx)
{
    uint32_t type_id = 0;
    if (ctx->btf_metadata.btf != NULL) {
        type_id = psabtf_get_member_type_id_by_name(ctx->btf_metadata.btf, ctx->reg.btf_type_id, "value");
    }

    return parse_struct_type(&ctx->btf_metadata, type_id, ctx->reg.value_size, &ctx->value_fds);
}

int psabpf_register_ctx_name(psabpf_context_t *psabpf_ctx, psabpf_register_context_t *ctx, const char *name) {
    if (psabpf_ctx == NULL || ctx == NULL || name == NULL)
        return EINVAL;

    if (load_btf(psabpf_ctx, &ctx->btf_metadata) != NO_ERROR) {
        fprintf(stderr, "couldn't find a BTF info\n");
    }

    int ret = open_bpf_map(psabpf_ctx, name, &ctx->btf_metadata, &ctx->reg);
    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't open a register %s\n", name);
        return ret;
    }

    if (parse_key_type(ctx) != NO_ERROR) {
        fprintf(stderr, "%s: couldn't get key BTF info of a Register instance\n", name);
        return EOPNOTSUPP;
    }

    if (parse_value_type(ctx) != NO_ERROR) {
        fprintf(stderr, "%s: couldn't get value BTF info of a Register instance\n", name);
        return EOPNOTSUPP;
    }

    return NO_ERROR;
}

void psabpf_register_entry_init(psabpf_register_entry_t *entry) {
    if (entry == NULL)
        return;

    memset(entry, 0, sizeof(psabpf_register_entry_t));
}

void psabpf_register_entry_free(psabpf_register_entry_t *entry) {
    if (entry == NULL)
        return;

    free_struct_field_set(&entry->entry_key);

    if (entry->raw_key != NULL)
        free(entry->raw_key);
    entry->raw_key = NULL;

    if (entry->raw_value != NULL)
        free(entry->raw_value);
    entry->raw_value = NULL;
}

int psabpf_register_entry_set_key(psabpf_register_entry_t *entry, const void *data, size_t data_len) {
    if (entry == NULL)
        return EINVAL;
    if (data == NULL || data_len < 1)
        return ENODATA;

    int ret = struct_field_set_append(&entry->entry_key, data, data_len);
    if (ret != NO_ERROR)
        fprintf(stderr, "couldn't append key to an entry: %s\n", strerror(ret));
    return ret;
}

int psabpf_register_entry_set_value(psabpf_register_entry_t *entry, const void *data, size_t data_len) {
    if (entry == NULL)
        return EINVAL;
    if (data == NULL || data_len < 1)
        return ENODATA;

    int ret = struct_field_set_append(&entry->entry_value, data, data_len);
    if (ret != NO_ERROR)
        fprintf(stderr, "couldn't append value to an entry: %s\n", strerror(ret));
    return ret;
}

static void *allocate_key_buffer(psabpf_register_context_t *ctx, psabpf_register_entry_t *entry)
{
    if (entry->raw_key != NULL)
        return entry->raw_key;  /* already allocated */

    entry->raw_key = malloc(ctx->reg.key_size);
    if (entry->raw_key == NULL)
        fprintf(stderr, "not enough memory\n");

    return entry->raw_key;
}

static void *allocate_value_buffer(psabpf_register_context_t *ctx, psabpf_register_entry_t *entry)
{
    if (entry->raw_value != NULL)
        return entry->raw_value;

    entry->raw_value = malloc(ctx->reg.value_size);
    if (entry->raw_value == NULL)
        fprintf(stderr, "not enough memory\n");

    return entry->raw_value;
}

psabpf_struct_field_t * psabpf_register_get_next_value_field(psabpf_register_context_t *ctx, psabpf_register_entry_t *entry)
{
    if (ctx == NULL || entry == NULL)
        return NULL;

    psabpf_struct_field_descriptor_t *fd;
    fd = get_struct_field_descriptor(&ctx->value_fds, entry->current_field_id);
    if (fd == NULL) {
        entry->current_field_id = 0;
        return NULL;
    }

    entry->current_field.type = fd->type;
    entry->current_field.data_len = fd->data_len;
    entry->current_field.name = fd->name;
    entry->current_field.data = entry->raw_value + fd->data_offset;

    entry->current_field_id = entry->current_field_id + 1;

    return &entry->current_field;
}

psabpf_struct_field_t * psabpf_register_get_next_index_field(psabpf_register_context_t *ctx, psabpf_register_entry_t *entry)
{
    if (ctx == NULL || entry == NULL)
        return NULL;

    psabpf_struct_field_descriptor_t *fd;
    fd = get_struct_field_descriptor(&ctx->key_fds, entry->current_field_id);
    if (fd == NULL) {
        entry->current_field_id = 0;
        return NULL;
    }

    entry->current_field.type = fd->type;
    entry->current_field.data_len = fd->data_len;
    entry->current_field.name = fd->name;
    entry->current_field.data = entry->raw_key + fd->data_offset;

    entry->current_field_id = entry->current_field_id + 1;

    return &entry->current_field;
}

psabpf_register_entry_t * psabpf_register_get_next(psabpf_register_context_t *ctx)
{
    if (ctx == NULL)
        return NULL;

    if (allocate_key_buffer(ctx, &ctx->current_entry) == NULL)
        return NULL;

    /* on first call ctx->prev_entry_ke must be NULL */
    if (bpf_map_get_next_key(ctx->reg.fd, ctx->prev_entry_key, ctx->current_entry.raw_key) != 0) {
        /* no more entries, prepare for next iteration */
        if (ctx->prev_entry_key != NULL)
            free(ctx->prev_entry_key);
        ctx->prev_entry_key = NULL;

        return NULL;
    }

    if (ctx->prev_entry_key == NULL) {
        ctx->prev_entry_key = malloc(ctx->reg.key_size);
        if (ctx->prev_entry_key == NULL) {
            fprintf(stderr, "not enough memory\n");
            return NULL;
        }
    }

    memcpy(ctx->prev_entry_key, ctx->current_entry.raw_key, ctx->reg.key_size);

    if (allocate_value_buffer(ctx, &ctx->current_entry) == NULL)
        return NULL;

    int ret = bpf_map_lookup_elem(ctx->reg.fd, ctx->current_entry.raw_key, ctx->current_entry.raw_value);
    if (ret != NO_ERROR) {
        fprintf(stderr, "failed to read Register entry: %s\n", strerror(ret));
        return NULL;
    }

    return &ctx->current_entry;
}

int psabpf_register_get(psabpf_register_context_t *ctx, psabpf_register_entry_t *entry)
{
    if (allocate_key_buffer(ctx, entry) == NULL)
        return ENOMEM;

    int ret = construct_struct_from_fields(&entry->entry_key, &ctx->key_fds, entry->raw_key, ctx->reg.key_size);
    if (ret != NO_ERROR)
        return ret;

    if (allocate_value_buffer(ctx, entry) == NULL)
        return ENOMEM;

    ret = bpf_map_lookup_elem(ctx->reg.fd, entry->raw_key, entry->raw_value);
    if (ret != 0) {
        ret = errno;
        fprintf(stderr, "failed to read Register entry: %s\n", strerror(ret));
        return ret;
    }

    return NO_ERROR;
}

int psabpf_register_set(psabpf_register_context_t *ctx, psabpf_register_entry_t *entry) {
    if (allocate_key_buffer(ctx, entry) == NULL)
        return ENOMEM;

    int ret = construct_struct_from_fields(&entry->entry_key, &ctx->key_fds, entry->raw_key, ctx->reg.key_size);
    if (ret != NO_ERROR)
        return ret;

    if (allocate_value_buffer(ctx, entry) == NULL)
        return ENOMEM;

    ret = construct_struct_from_fields(&entry->entry_value, &ctx->value_fds, entry->raw_value, ctx->reg.value_size);
    if (ret != NO_ERROR)
        return ret;

    ret = bpf_map_update_elem(ctx->reg.fd, entry->raw_key, entry->raw_value, 0);
    if (ret != NO_ERROR) {
        fprintf(stderr, "failed to set a register: %s\n", strerror(ret));
        return ret;
    }

    return NO_ERROR;
}

int psabpf_register_reset(psabpf_register_context_t *ctx, psabpf_register_entry_t *entry) {
    // TODO implement
    return NO_ERROR;
}
