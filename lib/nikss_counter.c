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
#include <stdlib.h>
#include <string.h>

#include <nikss/nikss.h>

#include "bpf_defs.h"
#include "btf.h"
#include "common.h"
#include "nikss_counter.h"

#define MAX_COUNTER_VALUE_SIZE 16

#define MAX_COUNTER_VALUE_SIZE_SINGLE_FIELD 8
#define MAX_COUNTER_VALUE_SIZE_BOTH_FIELDS  MAX_COUNTER_VALUE_SIZE

void nikss_counter_ctx_init(nikss_counter_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    memset(ctx, 0, sizeof(nikss_counter_context_t));
    ctx->counter.fd = -1;
    init_btf(&ctx->btf_metadata);
}

void nikss_counter_ctx_free(nikss_counter_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    free_btf(&ctx->btf_metadata);
    close_object_fd(&(ctx->counter.fd));
    free_struct_field_descriptor_set(&ctx->key_fds);
    nikss_counter_entry_free(&ctx->current_entry);

    if (ctx->prev_entry_key != NULL) {
        free(ctx->prev_entry_key);
    }
    ctx->prev_entry_key= NULL;
}

nikss_counter_type_t get_counter_type(nikss_btf_t *btf, uint32_t type_id)
{
    const struct btf_type *type = btf_get_type_by_id(btf->btf, type_id);
    if (btf_kind(type) != BTF_KIND_STRUCT) {
        return NIKSS_COUNTER_TYPE_UNKNOWN;
    }

    unsigned value_entries = btf_vlen(type);
    if (value_entries != COUNTER_PACKETS_OR_BYTES_STRUCT_ENTRIES &&
        value_entries != COUNTER_PACKETS_AND_BYTES_STRUCT_ENTRIES) {
        return NIKSS_COUNTER_TYPE_UNKNOWN;
    }

    /* Allowed field names: "packets", "bytes" */
    bool has_bytes = false;
    bool has_packets = false;
    const struct btf_member *m = btf_members(type);
    for (unsigned i = 0; i < value_entries; i++, m++) {
        const char *field_name = btf__name_by_offset(btf->btf, m->name_off);
        if (field_name == NULL) {
            return NIKSS_COUNTER_TYPE_UNKNOWN;
        }

        if (strcmp(field_name, "bytes") == 0) {
            has_bytes = true;
        } else if (strcmp(field_name, "packets") == 0) {
            has_packets = true;
        } else {
            return NIKSS_COUNTER_TYPE_UNKNOWN;
        }
    }

    /* Decode counter type */
    nikss_counter_type_t counter_type = NIKSS_COUNTER_TYPE_UNKNOWN;
    if (has_bytes == true && has_packets == true) {
        counter_type = NIKSS_COUNTER_TYPE_BYTES_AND_PACKETS;
    } else if (has_bytes == true && has_packets == false) {
        counter_type = NIKSS_COUNTER_TYPE_BYTES;
    } else if (has_bytes == false && has_packets == true) {
        counter_type = NIKSS_COUNTER_TYPE_PACKETS;
    }

    return counter_type;
}

static int parse_counter_value(nikss_counter_context_t *ctx)
{
    ctx->counter_type = get_counter_type(&ctx->btf_metadata, ctx->counter.value_type_id);
    if (ctx->counter_type == NIKSS_COUNTER_TYPE_UNKNOWN) {
        return EINVAL;
    }

    /* Validate counter size - up to 64 bits per counter*/
    if ((ctx->counter_type == NIKSS_COUNTER_TYPE_BYTES_AND_PACKETS &&
            ctx->counter.value_size > MAX_COUNTER_VALUE_SIZE_BOTH_FIELDS) ||
        (ctx->counter_type != NIKSS_COUNTER_TYPE_BYTES_AND_PACKETS &&
            ctx->counter.value_size > MAX_COUNTER_VALUE_SIZE_SINGLE_FIELD)) {
        return ENOTSUP;
    }

    return NO_ERROR;
}

static int parse_counter_key(nikss_counter_context_t *ctx)
{
    return parse_struct_type(&ctx->btf_metadata, ctx->counter.key_type_id, ctx->counter.key_size, &ctx->key_fds);
}

int nikss_counter_ctx_name(nikss_context_t *nikss_ctx, nikss_counter_context_t *ctx, const char *name)
{
    if (nikss_ctx == NULL || ctx == NULL || name == NULL) {
        return EINVAL;
    }

    /* get the BTF, will not work without it because there is too many possible configurations */
    if (load_btf(nikss_ctx, &ctx->btf_metadata) != NO_ERROR) {
        fprintf(stderr, "couldn't find BTF info\n");
        return ENOTSUP;
    }

    int ret = open_bpf_map(nikss_ctx, name, &ctx->btf_metadata, &ctx->counter);
    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't open counter %s\n", name);
        return ret;
    }

    if (parse_counter_value(ctx) != NO_ERROR) {
        fprintf(stderr, "%s: not a Counter instance\n", name);
        close_object_fd(&ctx->counter.fd);
        return EOPNOTSUPP;
    }

    return parse_counter_key(ctx);
}

void nikss_counter_entry_init(nikss_counter_entry_t *entry)
{
    if (entry == NULL) {
        return;
    }

    memset(entry, 0, sizeof(nikss_counter_entry_t));
}

void nikss_counter_entry_free(nikss_counter_entry_t *entry)
{
    if (entry == NULL) {
        return;
    }

    free_struct_field_set(&entry->entry_key);

    if (entry->raw_key != NULL) {
        free(entry->raw_key);
    }
    entry->raw_key = NULL;
}

int nikss_counter_entry_set_key(nikss_counter_entry_t *entry, const void *data, size_t data_len)
{
    if (entry == NULL) {
        return EINVAL;
    }
    if (data == NULL || data_len < 1) {
        return ENODATA;
    }

    int ret = struct_field_set_append(&entry->entry_key, data, data_len);
    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't append key to an entry: %s\n", strerror(ret));
    }
    return ret;
}

nikss_struct_field_t *nikss_counter_entry_get_next_key(nikss_counter_context_t *ctx, nikss_counter_entry_t *entry)
{
    if (ctx == NULL || entry == NULL) {
        return NULL;
    }

    if (entry->raw_key == NULL) {
        return NULL;
    }

    nikss_struct_field_descriptor_t *fd = NULL;
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

nikss_counter_type_t nikss_counter_get_type(nikss_counter_context_t *ctx)
{
    if (ctx == NULL) {
        return NIKSS_COUNTER_TYPE_UNKNOWN;
    }

    return ctx->counter_type;
}

void nikss_counter_entry_set_packets(nikss_counter_entry_t *entry, nikss_counter_value_t packets)
{
    if (entry == NULL) {
        return;
    }
    entry->packets = packets;
}

void nikss_counter_entry_set_bytes(nikss_counter_entry_t *entry, nikss_counter_value_t bytes)
{
    if (entry == NULL) {
        return;
    }
    entry->bytes = bytes;
}

nikss_counter_value_t nikss_counter_entry_get_packets(nikss_counter_entry_t *entry)
{
    if (entry == NULL) {
        return 0;
    }
    return entry->packets;
}

nikss_counter_value_t nikss_counter_entry_get_bytes(nikss_counter_entry_t *entry)
{
    if (entry == NULL) {
        return 0;
    }
    return entry->bytes;
}

static void *allocate_key_buffer(nikss_counter_context_t *ctx, nikss_counter_entry_t *entry)
{
    if (entry->raw_key != NULL) {
        return entry->raw_key;  /* already allocated */
    }

    entry->raw_key = malloc(ctx->counter.key_size);
    if (entry->raw_key == NULL) {
        fprintf(stderr, "not enough memory\n");
    }

    return entry->raw_key;
}

int convert_counter_data_to_entry(const char *data, size_t counter_size,
                                  nikss_counter_type_t counter_type, nikss_counter_entry_t *entry)
{
    entry->bytes = 0;
    entry->packets = 0;

    if (counter_type == NIKSS_COUNTER_TYPE_BYTES) {
        memcpy(&entry->bytes, &data[0], counter_size);
    } else if (counter_type == NIKSS_COUNTER_TYPE_PACKETS) {
        memcpy(&entry->packets, &data[0], counter_size);
    } else if (counter_type == NIKSS_COUNTER_TYPE_BYTES_AND_PACKETS) {
        counter_size = counter_size / 2;
        memcpy(&entry->bytes, &data[0], counter_size);
        memcpy(&entry->packets, &data[counter_size], counter_size);
    }

    return NO_ERROR;
}

static int read_and_parse_counter_value(nikss_counter_context_t *ctx, nikss_counter_entry_t *entry)
{
    char value[MAX_COUNTER_VALUE_SIZE];
    int ret = bpf_map_lookup_elem(ctx->counter.fd, entry->raw_key, &value[0]);
    if (ret != 0) {
        ret = errno;
        fprintf(stderr, "failed to read Counter entry: %s\n", strerror(ret));
        return ret;
    }

    /* raw_key is always used as a data source for user request on next field, so convert it to right byte order */
    fix_struct_data_byte_order(&ctx->key_fds, entry->raw_key, ctx->counter.key_size);

    return convert_counter_data_to_entry(value, ctx->counter.value_size, ctx->counter_type, entry);
}

int nikss_counter_get(nikss_counter_context_t *ctx, nikss_counter_entry_t *entry)
{
    if (ctx == NULL || entry == NULL) {
        return EINVAL;
    }

    if (allocate_key_buffer(ctx, entry) == NULL) {
        return ENOMEM;
    }

    int ret = construct_struct_from_fields(&entry->entry_key, &ctx->key_fds, entry->raw_key, ctx->counter.key_size);
    if (ret != NO_ERROR) {
        return ret;
    }

    return read_and_parse_counter_value(ctx, entry);
}

nikss_counter_entry_t *nikss_counter_get_next(nikss_counter_context_t *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    if (allocate_key_buffer(ctx, &ctx->current_entry) == NULL) {
        return NULL;
    }

    /* on first call ctx->prev_entry_ke must be NULL */
    if (bpf_map_get_next_key(ctx->counter.fd, ctx->prev_entry_key, ctx->current_entry.raw_key) != 0) {
        /* no more entries, prepare for next iteration */
        if (ctx->prev_entry_key != NULL) {
            free(ctx->prev_entry_key);
        }
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
    if (read_and_parse_counter_value(ctx, &ctx->current_entry) != NO_ERROR) {
        return NULL;
    }

    return &ctx->current_entry;
}

int convert_counter_entry_to_data(nikss_counter_context_t *ctx, nikss_counter_entry_t *entry, char *buffer)
{
    size_t counter_size = ctx->counter.value_size;
    if (ctx->counter_type == NIKSS_COUNTER_TYPE_BYTES) {
        memcpy(buffer, &entry->bytes, counter_size);
    } else if (ctx->counter_type == NIKSS_COUNTER_TYPE_PACKETS) {
        memcpy(buffer, &entry->packets, counter_size);
    } else if (ctx->counter_type == NIKSS_COUNTER_TYPE_BYTES_AND_PACKETS) {
        counter_size = counter_size / 2;
        memcpy(buffer, &entry->bytes, counter_size);
        memcpy(buffer + counter_size, &entry->packets, counter_size);
    } else {
        return EBADF;
    }

    return NO_ERROR;
}

static bool is_zero_counter_value(const char *buffer, size_t buffer_len)
{
    for (size_t i = 0; i < buffer_len; i++) {
        if (buffer[i] != 0) {
            return false;
        }
    }
    return true;
}

static int set_all_counters(nikss_counter_context_t *ctx, void *encoded_value, bool remove_entry_allowed)
{
    char * key = malloc(ctx->counter.key_size);
    char * next_key = malloc(ctx->counter.key_size);
    int error_code = NO_ERROR;
    int ret = 0;
    bool can_remove_entries = is_zero_counter_value(encoded_value, ctx->counter.value_size);

    if (ctx->counter.type == BPF_MAP_TYPE_ARRAY || !remove_entry_allowed) {
        can_remove_entries = false;
    }

    if (key == NULL || next_key == NULL) {
        fprintf(stderr, "not enough memory\n");
        error_code = ENOMEM;
        goto clean_up;
    }

    if (bpf_map_get_next_key(ctx->counter.fd, NULL, next_key) != 0) {
        goto clean_up;  /* table empty */
    }

    do {
        /* Swap buffers, so next_key will become key and next_key may be reused */
        char * tmp_key = next_key;
        next_key = key;
        key = tmp_key;

        if (can_remove_entries) {
            ret = bpf_map_delete_elem(ctx->counter.fd, key);
        } else {
            ret = bpf_map_update_elem(ctx->counter.fd, key, encoded_value, 0);
        }

        if (ret != 0) {
            error_code = errno;
            fprintf(stderr, "failed to set all entries: %s\n", strerror(error_code));
            break;
        }

    } while (bpf_map_get_next_key(ctx->counter.fd, key, next_key) == 0);

clean_up:
    if (key) {
        free(key);
    }
    if (next_key) {
        free(next_key);
    }
    return error_code;
}

static int do_counter_set(nikss_counter_context_t *ctx, nikss_counter_entry_t *entry, bool remove_entry_allowed)
{
    if (ctx == NULL || entry == NULL) {
        return EINVAL;
    }

    char value[MAX_COUNTER_VALUE_SIZE];
    if (convert_counter_entry_to_data(ctx, entry, &value[0]) != NO_ERROR) {
        return EINVAL;
    }

    if (entry->entry_key.n_fields == 0) {
        return set_all_counters(ctx, &value[0], remove_entry_allowed);
    }

    if (allocate_key_buffer(ctx, entry) == NULL) {
        return ENOMEM;
    }

    int ret = construct_struct_from_fields(&entry->entry_key, &ctx->key_fds, entry->raw_key, ctx->counter.key_size);
    if (ret != NO_ERROR) {
        return ret;
    }

    if (remove_entry_allowed &&
        ctx->counter.type == BPF_MAP_TYPE_HASH &&
        is_zero_counter_value(&value[0], ctx->counter.value_size)) {
        ret = bpf_map_delete_elem(ctx->counter.fd, entry->raw_key);
    } else {
        ret = bpf_map_update_elem(ctx->counter.fd, entry->raw_key, &value[0], 0);
    }
    if (ret != 0) {
        ret = errno;
        fprintf(stderr, "failed to set an entry: %s\n", strerror(ret));
    }

    return ret;
}

int nikss_counter_set(nikss_counter_context_t *ctx, nikss_counter_entry_t *entry)
{
    return do_counter_set(ctx, entry, false);
}

int nikss_counter_reset(nikss_counter_context_t *ctx, nikss_counter_entry_t *entry)
{
    if (ctx == NULL || entry == NULL) {
        return EINVAL;
    }

    entry->bytes = 0;
    entry->packets = 0;

    return do_counter_set(ctx, entry, true);
}
