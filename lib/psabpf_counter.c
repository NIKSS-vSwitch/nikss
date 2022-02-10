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

void psabpf_counter_entry_init(psabpf_counter_entry_t *entry)
{
    if (entry == NULL)
        return;

    memset(entry, 0, sizeof(psabpf_counter_entry_t));
}

void psabpf_counter_entry_free(psabpf_counter_entry_t *entry)
{
    if (entry == NULL)
        return;

    free_struct_field_set(&entry->entry_key);

    if (entry->raw_key != NULL)
        free(entry->raw_key);
    entry->raw_key = NULL;
}

int psabpf_counter_entry_set_key(psabpf_counter_entry_t *entry, void *data, size_t data_len)
{
    if (entry == NULL)
        return EINVAL;
    if (data == NULL || data_len < 1)
        return ENODATA;

    return struct_field_set_append(&entry->entry_key, data, data_len);
}

psabpf_struct_field_t *psabpf_counter_entry_get_next_key(psabpf_counter_context_t *ctx, psabpf_counter_entry_t *entry)
{
    if (ctx == NULL || entry == NULL)
        return NULL;

    if (entry->raw_key == NULL)
        return NULL;

    psabpf_struct_field_descriptor_t *fd;
    fd = get_struct_field_descriptor(&ctx->key_fds, entry->current_key_id);
    if (fd == NULL) {
        entry->current_key_id = 0;
        return NULL;
    }

    entry->current_field.type = fd->type;
    entry->current_field.data_len = fd->data_len;
    entry->current_field.name = fd->name;
    entry->current_field.data = entry->raw_key + fd->data_offset;

    entry->current_key_id = entry->current_key_id + 1;

    return &entry->current_field;
}

void psabpf_counter_entry_set_packets(psabpf_counter_entry_t *entry, psabpf_counter_value_t packets)
{
    if (entry == NULL)
        return;
    entry->packets = packets;
}

void psabpf_counter_entry_set_bytes(psabpf_counter_entry_t *entry, psabpf_counter_value_t bytes)
{
    if (entry == NULL)
        return;
    entry->bytes = bytes;
}

psabpf_counter_value_t psabpf_counter_entry_get_packets(psabpf_counter_entry_t *entry)
{
    if (entry == NULL)
        return 0;

    if (entry->counter_type == PSABPF_COUNTER_TYPE_PACKETS ||
        entry->counter_type == PSABPF_COUNTER_TYPE_BYTES_AND_PACKETS)
        return entry->packets;

    return 0;
}

psabpf_counter_value_t psabpf_counter_entry_get_bytes(psabpf_counter_entry_t *entry)
{
    if (entry == NULL)
        return 0;

    if (entry->counter_type == PSABPF_COUNTER_TYPE_BYTES ||
        entry->counter_type == PSABPF_COUNTER_TYPE_BYTES_AND_PACKETS)
        return entry->bytes;

    return 0;
}

static void *allocate_key_buffer(psabpf_counter_context_t *ctx, psabpf_counter_entry_t *entry)
{
    if (entry->raw_key != NULL)
        return entry->raw_key;  /* already allocated */

    entry->raw_key = malloc(ctx->counter.key_size);
    if (entry->raw_key == NULL)
        fprintf(stderr, "not enough memory\n");

    return entry->raw_key;
}

int psabpf_counter_get(psabpf_counter_context_t *ctx, psabpf_counter_entry_t *entry)
{
    if (ctx == NULL || entry == NULL)
        return EINVAL;

    if (allocate_key_buffer(ctx, entry) == NULL)
        return ENOMEM;

    int ret = construct_struct_from_fields(&entry->entry_key, &ctx->key_fds, entry->raw_key, ctx->counter.key_size);
    if (ret != NO_ERROR)
        return ret;

    uint8_t value[16];
    ret = bpf_map_lookup_elem(ctx->counter.fd, entry->raw_key, &value[0]);
    if (ret != 0) {
        ret = errno;
        fprintf(stderr, "failed to read Counter entry: %s\n", strerror(ret));
        return ret;
    }

    size_t counter_size = ctx->counter.value_size;
    if (ctx->counter_type == PSABPF_COUNTER_TYPE_BYTES)
        memcpy(&entry->bytes, &value[0], counter_size);
    else if (ctx->counter_type == PSABPF_COUNTER_TYPE_PACKETS)
        memcpy(&entry->packets, &value[0], counter_size);
    else if (ctx->counter_type == PSABPF_COUNTER_TYPE_BYTES_AND_PACKETS) {
        counter_size = counter_size / 2;
        memcpy(&entry->bytes, &value[0], counter_size);
        memcpy(&entry->packets, &value[counter_size], counter_size);
    }

    return NO_ERROR;
}

psabpf_counter_entry_t *psabpf_counter_get_next(psabpf_counter_context_t *ctx)
{
    return NULL;
}

int psabpf_counter_set(psabpf_counter_context_t *ctx, psabpf_counter_entry_t *entry)
{
    if (ctx == NULL || entry == NULL)
        return EINVAL;

    return NO_ERROR;
}

int psabpf_counter_reset(psabpf_counter_context_t *ctx, psabpf_counter_entry_t *entry)
{
    if (ctx == NULL || entry == NULL)
        return EINVAL;

    entry->bytes = 0;
    entry->packets = 0;

    return psabpf_counter_set(ctx, entry);
}
