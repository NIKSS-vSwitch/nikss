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
#include <bpf/btf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <nikss.h>

#include "btf.h"
#include "common.h"
#include "nikss_meter.h"
#include "nikss_table.h"

/**
 * This function comes from DPDK
 * https://github.com/DPDK/dpdk/blob/0bf5832222971a0154c9150d4a7a4b82ecbc9ddb/lib/meter/rte_meter.h
 * @param rate In byte/s or packet/s
 * @param period In nanoseconds
 * @param unit_per_period In byte or packet
 */
static void convert_rate(const nikss_meter_value_t *rate, nikss_meter_value_t *period,
                         nikss_meter_value_t *unit_per_period)
{
    if (*rate == 0) {
        *unit_per_period = 0;
        *period = 0;
        return;
    }

    *period = ((nikss_meter_value_t) (NS_IN_S)) / (*rate);

    if (*period >= METER_PERIOD_MIN) {
        *unit_per_period = 1;
    } else {
        *unit_per_period = (uint64_t) ceil(METER_PERIOD_MIN / ((double) (*period)));
        *period = (NS_IN_S * (*unit_per_period)) / *rate;
    }
}

int convert_meter_data_to_entry(const nikss_meter_data_t *data, nikss_meter_entry_t *entry)
{
    if (entry == NULL || data == NULL) {
        return ENODATA;
    }

    nikss_meter_value_t pir = 0;
    nikss_meter_value_t cir = 0;

    if (data->pir_period != 0) {
        pir = (NS_IN_S / data->pir_period) * data->pir_unit_per_period;
    }
    if (data->cir_period != 0) {
        cir = (NS_IN_S / data->cir_period) * data->cir_unit_per_period;
    }

    entry->pir = pir;
    entry->pbs = data->pbs;
    entry->cir = cir;
    entry->cbs = data->cbs;

    return NO_ERROR;
}

int convert_meter_entry_to_data(const nikss_meter_entry_t *entry, nikss_meter_data_t *data)
{
    if (entry == NULL || data == NULL) {
        return ENODATA;
    }

    convert_rate(&entry->pir, &data->pir_period, &data->pir_unit_per_period);
    convert_rate(&entry->cir, &data->cir_period, &data->cir_unit_per_period);

    data->pbs = entry->pbs;
    data->pbs_left = entry->pbs;
    data->cbs = entry->cbs;
    data->cbs_left = entry->cbs;

    return NO_ERROR;
}

void nikss_meter_entry_init(nikss_meter_entry_t *entry)
{
    if (entry == NULL) {
        return;
    }

    memset(entry, 0, sizeof(nikss_meter_entry_t));
}

void nikss_meter_entry_free(nikss_meter_entry_t *entry)
{
    if (entry == NULL) {
        return;
    }

    if (entry->raw_index != NULL) {
        free(entry->raw_index);
    }
    entry->raw_index = NULL;

    free_struct_field_set(&entry->index_sfs);

    memset(entry, 0, sizeof(nikss_meter_entry_t));
}

int nikss_meter_entry_index(nikss_meter_entry_t *entry, const char *data, size_t size)
{
    if (entry == NULL || data == NULL || size < 1) {
        return ENODATA;
    }

    int ret = struct_field_set_append(&entry->index_sfs, data, size);
    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't append key to an entry: %s\n", strerror(ret));
    }

    return ret;
}

int nikss_meter_entry_data(nikss_meter_entry_t *entry,
                           nikss_meter_value_t pir,
                           nikss_meter_value_t pbs,
                           nikss_meter_value_t cir,
                           nikss_meter_value_t cbs)
{
    if (entry == NULL) {
        return ENODATA;
    }

    entry->pir = pir;
    entry->pbs = pbs;
    entry->cir = cir;
    entry->cbs = cbs;

    return NO_ERROR;
}

int nikss_meter_entry_get_data(nikss_meter_entry_t *entry,
                               nikss_meter_value_t *pir,
                               nikss_meter_value_t *pbs,
                               nikss_meter_value_t *cir,
                               nikss_meter_value_t *cbs)
{
    if (entry == NULL) {
        return ENODATA;
    }

    if (pir != NULL) {
        *pir = entry->pir;
    }
    if (pbs != NULL) {
        *pbs = entry->pbs;
    }
    if (cir != NULL) {
        *cir = entry->cir;
    }
    if (cbs != NULL) {
        *cbs = entry->cbs;
    }

    return NO_ERROR;
}

nikss_struct_field_t * nikss_meter_entry_get_next_index_field(nikss_meter_ctx_t *ctx, nikss_meter_entry_t *entry)
{
    if (ctx == NULL || entry == NULL) {
        return NULL;
    }

    nikss_struct_field_descriptor_t *fd = NULL;
    fd = get_struct_field_descriptor(&ctx->index_fds, entry->current_index_field_id);
    if (fd == NULL) {
        entry->current_index_field_id = 0;
        return NULL;
    }

    entry->current_index_field.type = fd->type;
    entry->current_index_field.data_len = fd->data_len;
    entry->current_index_field.name = fd->name;
    entry->current_index_field.data = entry->raw_index + fd->data_offset;

    entry->current_index_field_id = entry->current_index_field_id + 1;

    return &entry->current_index_field;
}

void nikss_meter_ctx_init(nikss_meter_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    memset(ctx, 0, sizeof(nikss_meter_ctx_t));

    nikss_meter_entry_init(&ctx->current_entry);
    ctx->meter.fd = -1;
    init_btf(&ctx->btf_metadata);
}

void nikss_meter_ctx_free(nikss_meter_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    nikss_meter_entry_free(&ctx->current_entry);
    free_btf(&ctx->btf_metadata);
    free_struct_field_descriptor_set(&ctx->index_fds);
    close_object_fd(&ctx->meter.fd);

    if (ctx->previous_index != NULL) {
        free(ctx->previous_index);
    }
    ctx->previous_index = NULL;
}

int nikss_meter_ctx_name(nikss_meter_ctx_t *ctx, nikss_context_t *nikss_ctx, const char *name)
{
    if (ctx == NULL || nikss_ctx == NULL || name == NULL) {
        return EPERM;
    }

    if (load_btf(nikss_ctx, &ctx->btf_metadata) != NO_ERROR) {
        fprintf(stderr, "couldn't find a BTF info\n");
    }

    int ret = open_bpf_map(nikss_ctx, name, &ctx->btf_metadata, &ctx->meter);
    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't open meter %s: %s\n", name, strerror(ret));
        return ret;
    }

    if (sizeof(nikss_meter_data_t) > ctx->meter.value_size) {
        /* cppcheck-suppress invalidPrintfArgType_uint ; cppcheck failed to recognize a real type of size_t */
        fprintf(stderr, "Meter data has bigger size "
                        "(%lu) than meter definition value size (%u)!\n",
                sizeof(nikss_meter_data_t), ctx->meter.value_size);
        return EINVAL;
    }

    /* Parses index type */
    ret = parse_struct_type(&ctx->btf_metadata, ctx->meter.key_type_id, ctx->meter.key_size, &ctx->index_fds);
    if (ret != NO_ERROR) {
        fprintf(stderr, "failed to parse meter type: %s\n", strerror(ret));
        return ret;
    }

    return NO_ERROR;
}

int nikss_meter_entry_get(nikss_meter_ctx_t *ctx, nikss_meter_entry_t *entry)
{
    int return_code = NO_ERROR;
    uint64_t bpf_flags = BPF_F_LOCK;
    char *value_buffer = NULL;

    if (ctx == NULL || entry == NULL) {
        return EINVAL;
    }

    if (entry->index_sfs.n_fields == 0) {
        fprintf(stderr, "Index not provided");
        return EINVAL;
    }

    if (entry->raw_index == NULL) {
        entry->raw_index = malloc(ctx->meter.key_size);
    }
    value_buffer = malloc(ctx->meter.value_size);
    if (entry->raw_index == NULL || value_buffer == NULL) {
        fprintf(stderr, "not enough memory\n");
        return_code = ENOMEM;
        goto clean_up;
    }

    memset(value_buffer, 0, ctx->meter.value_size);
    return_code = construct_struct_from_fields(&entry->index_sfs, &ctx->index_fds, entry->raw_index, ctx->meter.key_size);
    if (return_code != NO_ERROR) {
        goto clean_up;
    }

    return_code = bpf_map_lookup_elem_flags(ctx->meter.fd, entry->raw_index, value_buffer, bpf_flags);
    if (return_code != 0) {
        return_code = errno;
        fprintf(stderr, "failed to get meter: %s\n", strerror(errno));
        goto clean_up;
    }

    nikss_meter_data_t data;
    memcpy(&data, value_buffer, sizeof(data));
    return_code = convert_meter_data_to_entry(&data, entry);

clean_up:
    free(value_buffer);
    return return_code;
}

nikss_meter_entry_t *nikss_meter_get_next(nikss_meter_ctx_t *ctx)
{
    nikss_meter_entry_t *ret_instance = NULL;
    void *next_key = NULL;
    void *value_buffer = NULL;

    if (ctx == NULL) {
        return NULL;
    }

    next_key = malloc(ctx->meter.key_size);
    value_buffer = malloc(ctx->meter.value_size);
    if (next_key == NULL || value_buffer == NULL) {
        fprintf(stderr, "not enough memory\n");
        goto clean_up;
    }

    if (bpf_map_get_next_key(ctx->meter.fd, ctx->previous_index, next_key) != 0) {
        /* restart iteration */
        if (ctx->previous_index != NULL) {
            free(ctx->previous_index);
        }
        ctx->previous_index = NULL;

        goto clean_up;
    }

    if (ctx->previous_index == NULL) {
        ctx->previous_index = malloc(ctx->meter.key_size);
    }
    if (ctx->previous_index == NULL) {
        fprintf(stderr, "not enough memory\n");
        goto clean_up;
    }

    if (ctx->current_entry.raw_index != NULL) {
        free(ctx->current_entry.raw_index);
    }
    ctx->current_entry.raw_index = next_key;
    memcpy(ctx->previous_index, next_key, ctx->meter.key_size);
    next_key = NULL;

    int return_code = bpf_map_lookup_elem(ctx->meter.fd, ctx->current_entry.raw_index, value_buffer);
    if (return_code != 0) {
        return_code = errno;
        fprintf(stderr, "failed to get entry: %s\n", strerror(return_code));
        goto clean_up;
    }

    nikss_meter_data_t data;
    memcpy(&data, value_buffer, sizeof(data));
    return_code = convert_meter_data_to_entry(&data, &ctx->current_entry);
    if (return_code != NO_ERROR) {
        goto clean_up;
    }

    ret_instance = &ctx->current_entry;

clean_up:
    if (next_key != NULL) {
        free(next_key);
    }
    if (value_buffer != NULL) {
        free(value_buffer);
    }

    return ret_instance;
}

int nikss_meter_entry_update(nikss_meter_ctx_t *ctx, nikss_meter_entry_t *entry)
{
    int return_code = NO_ERROR;
    uint64_t bpf_flags = BPF_F_LOCK;
    char *value_buffer = NULL;
    nikss_meter_data_t data;

    if (ctx == NULL || entry == NULL) {
        return EINVAL;
    }

    if (entry->index_sfs.n_fields == 0) {
        fprintf(stderr, "Index not provided");
        return EINVAL;
    }

    return_code = convert_meter_entry_to_data(entry, &data);
    if (return_code != NO_ERROR) {
        return return_code;
    }

    if (entry->raw_index == NULL) {
        entry->raw_index = malloc(ctx->meter.key_size);
    }
    value_buffer = malloc(ctx->meter.value_size);
    if (entry->raw_index == NULL || value_buffer == NULL) {
        fprintf(stderr, "not enough memory\n");
        return_code = ENOMEM;
        goto clean_up;
    }

    memset(value_buffer, 0, ctx->meter.value_size);
    memcpy(value_buffer, &data, sizeof(data));
    return_code = construct_struct_from_fields(&entry->index_sfs, &ctx->index_fds, entry->raw_index, ctx->meter.key_size);
    if (return_code != NO_ERROR) {
        goto clean_up;
    }

    return_code = bpf_map_update_elem(ctx->meter.fd, entry->raw_index, value_buffer, bpf_flags);
    if (return_code != 0) {
        return_code = errno;
        fprintf(stderr, "failed to set up meter: %s\n", strerror(errno));
        goto clean_up;
    }

clean_up:
    free(value_buffer);
    return return_code;
}

int nikss_meter_entry_reset(nikss_meter_ctx_t *ctx, nikss_meter_entry_t *entry)
{
    if (ctx == NULL) {
        return EINVAL;
    }

    /* Remove all entries if nikss_meter_entry_index were not executed on meter entry. */
    if (entry == NULL || entry->index_sfs.n_fields < 1) {
        return delete_all_map_entries(&ctx->meter);
    }

    if (ctx->meter.type == BPF_MAP_TYPE_ARRAY) {
        int return_code = nikss_meter_entry_data(entry, 0, 0, 0, 0);
        if (return_code != NO_ERROR) {
            return return_code;
        }
        return nikss_meter_entry_update(ctx, entry);
    }

    void *key_buffer = malloc(ctx->meter.key_size);
    if (key_buffer == NULL) {
        fprintf(stderr, "not enough memory\n");
        return ENOMEM;
    }

    int return_code = construct_struct_from_fields(&entry->index_sfs, &ctx->index_fds, key_buffer, ctx->meter.key_size);
    if (return_code != NO_ERROR) {
        goto clean_up;
    }

    if (bpf_map_delete_elem(ctx->meter.fd, key_buffer) != 0) {
        return_code = errno;
        fprintf(stderr, "failed to reset meter entry: %s\n", strerror(return_code));
    }

clean_up:
    free(key_buffer);
    return return_code;
}
