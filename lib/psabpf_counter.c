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

#define MAX_COUNTER_VALUE_SIZE 16

#define MAX_COUNTER_VALUE_SIZE_SINGLE_FIELD 8
#define MAX_COUNTER_VALUE_SIZE_BOTH_FIELDS  MAX_COUNTER_VALUE_SIZE

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
    psabpf_counter_entry_free(&ctx->current_entry);

    if (ctx->prev_entry_key != NULL)
        free(ctx->prev_entry_key);
    ctx->prev_entry_key= NULL;
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
    if ((ctx->counter_type == PSABPF_COUNTER_TYPE_BYTES_AND_PACKETS &&
            ctx->counter.value_size > MAX_COUNTER_VALUE_SIZE_BOTH_FIELDS) ||
        (ctx->counter_type != PSABPF_COUNTER_TYPE_BYTES_AND_PACKETS &&
            ctx->counter.value_size > MAX_COUNTER_VALUE_SIZE_SINGLE_FIELD))
        return ENOTSUP;

    return NO_ERROR;
}

static int parse_counter_key(psabpf_counter_context_t *ctx)
{
    uint32_t type_id = psabtf_get_member_type_id_by_name(ctx->btf_metadata.btf, ctx->counter.btf_type_id, "key");
    return parse_struct_type(&ctx->btf_metadata, type_id, ctx->counter.key_size, &ctx->key_fds);
}

int psabpf_counter_ctx_name(psabpf_context_t *psabpf_ctx, psabpf_counter_context_t *ctx, const char *name)
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

int psabpf_counter_entry_set_key(psabpf_counter_entry_t *entry, const void *data, size_t data_len)
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

psabpf_counter_type_t psabpf_counter_get_type(psabpf_counter_context_t *ctx)
{
    if (ctx == NULL)
        return PSABPF_COUNTER_TYPE_UNKNOWN;

    return ctx->counter_type;
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
    return entry->packets;
}

psabpf_counter_value_t psabpf_counter_entry_get_bytes(psabpf_counter_entry_t *entry)
{
    if (entry == NULL)
        return 0;
    return entry->bytes;
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

static int read_and_parse_counter_value(psabpf_counter_context_t *ctx, psabpf_counter_entry_t *entry)
{
    uint8_t value[MAX_COUNTER_VALUE_SIZE];
    int ret = bpf_map_lookup_elem(ctx->counter.fd, entry->raw_key, &value[0]);
    if (ret != 0) {
        ret = errno;
        fprintf(stderr, "failed to read Counter entry: %s\n", strerror(ret));
        return ret;
    }

    entry->bytes = 0;
    entry->packets = 0;

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

int psabpf_counter_get(psabpf_counter_context_t *ctx, psabpf_counter_entry_t *entry)
{
    if (ctx == NULL || entry == NULL)
        return EINVAL;

    if (allocate_key_buffer(ctx, entry) == NULL)
        return ENOMEM;

    int ret = construct_struct_from_fields(&entry->entry_key, &ctx->key_fds, entry->raw_key, ctx->counter.key_size);
    if (ret != NO_ERROR)
        return ret;

    return read_and_parse_counter_value(ctx, entry);
}

psabpf_counter_entry_t *psabpf_counter_get_next(psabpf_counter_context_t *ctx)
{
    if (ctx == NULL)
        return NULL;

    if (allocate_key_buffer(ctx, &ctx->current_entry) == NULL)
        return NULL;

    /* on first call ctx->prev_entry_ke must be NULL */
    if (bpf_map_get_next_key(ctx->counter.fd, ctx->prev_entry_key, ctx->current_entry.raw_key) != 0) {
        /* no more entries, prepare for next iteration */
        if (ctx->prev_entry_key != NULL)
            free(ctx->prev_entry_key);
        ctx->prev_entry_key = NULL;

        return NULL;
    }

    if (ctx->prev_entry_key == NULL) {
        ctx->prev_entry_key = malloc(ctx->counter.key_size);
        if (ctx->prev_entry_key == NULL) {
            fprintf(stderr, "not enough memory\n");
            return NULL;
        }
    }

    memcpy(ctx->prev_entry_key, ctx->current_entry.raw_key, ctx->counter.key_size);
    if (read_and_parse_counter_value(ctx, &ctx->current_entry) != NO_ERROR)
        return NULL;

    return &ctx->current_entry;
}

static int encode_counter_value(psabpf_counter_context_t *ctx, psabpf_counter_entry_t *entry, uint8_t *buffer)
{
    size_t counter_size = ctx->counter.value_size;
    if (ctx->counter_type == PSABPF_COUNTER_TYPE_BYTES)
        memcpy(buffer, &entry->bytes, counter_size);
    else if (ctx->counter_type == PSABPF_COUNTER_TYPE_PACKETS)
        memcpy(buffer, &entry->packets, counter_size);
    else if (ctx->counter_type == PSABPF_COUNTER_TYPE_BYTES_AND_PACKETS) {
        counter_size = counter_size / 2;
        memcpy(buffer, &entry->bytes, counter_size);
        memcpy(buffer + counter_size, &entry->packets, counter_size);
    } else
        return EBADF;

    return NO_ERROR;
}

static bool is_zero_counter_value(const uint8_t *buffer, size_t buffer_len)
{
    for (size_t i = 0; i < buffer_len; i++) {
        if (buffer[i] != 0)
            return false;
    }
    return true;
}

static int set_all_counters(psabpf_counter_context_t *ctx, psabpf_counter_entry_t *entry, void *encoded_value)
{
    char * key = malloc(ctx->counter.key_size);
    char * next_key = malloc(ctx->counter.key_size);
    int error_code = NO_ERROR;
    int ret;
    bool can_remove_entries = is_zero_counter_value(encoded_value, ctx->counter.value_size);

    if (ctx->counter.type == BPF_MAP_TYPE_HASH)
        can_remove_entries = false;

    if (key == NULL || next_key == NULL) {
        fprintf(stderr, "not enough memory\n");
        error_code = ENOMEM;
        goto clean_up;
    }

    if (bpf_map_get_next_key(ctx->counter.fd, NULL, next_key) != 0)
        goto clean_up;  /* table empty */

    do {
        /* Swap buffers, so next_key will become key and next_key may be reused */
        char * tmp_key = next_key;
        next_key = key;
        key = tmp_key;

        if (can_remove_entries)
            ret = bpf_map_delete_elem(ctx->counter.fd, entry->raw_key);
        else
            ret = bpf_map_update_elem(ctx->counter.fd, entry->raw_key, encoded_value, 0);

        if (ret != 0) {
            error_code = errno;
            break;
        }

    } while (bpf_map_get_next_key(ctx->counter.fd, key, next_key) == 0);

clean_up:
    if (key)
        free(key);
    if (next_key)
        free(next_key);
    return error_code;
}

// TODO: allow remove entries only for reset method
int psabpf_counter_set(psabpf_counter_context_t *ctx, psabpf_counter_entry_t *entry)
{
    if (ctx == NULL || entry == NULL)
        return EINVAL;

    uint8_t value[MAX_COUNTER_VALUE_SIZE];
    if (encode_counter_value(ctx, entry, &value[0]) != NO_ERROR)
        return EINVAL;

    if (entry->entry_key.n_fields == 0)
        return set_all_counters(ctx, entry, &value[0]);

    if (allocate_key_buffer(ctx, entry) == NULL)
        return ENOMEM;

    int ret = construct_struct_from_fields(&entry->entry_key, &ctx->key_fds, entry->raw_key, ctx->counter.key_size);
    if (ret != NO_ERROR)
        return ret;

    if (ctx->counter.type == BPF_MAP_TYPE_HASH && is_zero_counter_value(&value[0], ctx->counter.value_size)) {
        ret = bpf_map_delete_elem(ctx->counter.fd, entry->raw_key);
    } else {
        ret = bpf_map_update_elem(ctx->counter.fd, entry->raw_key, &value[0], 0);
    }
    if (ret != 0)
        ret = errno;

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
