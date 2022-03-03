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
#include <errno.h>
#include <math.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <linux/bpf.h>

#include <psabpf.h>
#include "btf.h"
#include "psabpf_meter.h"

/**
 * This function comes from DPDK
 * https://github.com/DPDK/dpdk/blob/0bf5832222971a0154c9150d4a7a4b82ecbc9ddb/lib/meter/rte_meter.h
 * @param rate In byte/s or packet/s
 * @param period In nanoseconds
 * @param unit_per_period In byte or packet
 */
static void convert_rate(const psabpf_meter_value_t *rate, psabpf_meter_value_t *period,
                         psabpf_meter_value_t *unit_per_period) {
    if (*rate == 0) {
        *unit_per_period = 0;
        *period = 0;
        return;
    }

    *period = (NS_IN_S) / ((psabpf_meter_value_t) *rate);

    if (*period >= METER_PERIOD_MIN) {
        *unit_per_period = 1;
    } else {
        *unit_per_period = (uint64_t) ceil(METER_PERIOD_MIN / *period);
        *period = (NS_IN_S * (*unit_per_period)) / *rate;
    }
}

static int convert_meter_data_to_entry(psabpf_meter_data_t *data, psabpf_meter_entry_t *entry) {
    if (entry == NULL || data == NULL)
        return ENODATA;

    psabpf_meter_value_t pir = 0;
    psabpf_meter_value_t cir = 0;

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

int convert_meter_entry_to_data(psabpf_meter_entry_t *entry, psabpf_meter_data_t *data) {
    if (entry == NULL || data == NULL)
        return ENODATA;

    convert_rate(&entry->pir, &data->pir_period, &data->pir_unit_per_period);
    convert_rate(&entry->cir, &data->cir_period, &data->cir_unit_per_period);

    data->pbs = entry->pbs;
    data->pbs_left = entry->pbs;
    data->cbs = entry->cbs;
    data->cbs_left = entry->cbs;

    return NO_ERROR;
}

static int open_meter(psabpf_meter_ctx_t *ctx, psabpf_context_t *psabpf_ctx, const char *name) {
    psabpf_bpf_map_descriptor_t metadata;
    int ret = open_bpf_map(psabpf_ctx, name, NULL, &metadata);

    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't open meter %s: %s\n", name, strerror(ret));
        return ret;
    }
    ctx->table_fd = metadata.fd;
    ctx->index_size = metadata.key_size;
    ctx->value_size = metadata.value_size;

    if (sizeof(psabpf_meter_data_t) > ctx->value_size) {
        fprintf(stderr, "Meter data has bigger size "
                        "(%lu) than meter definition value size (%u)!\n",
                sizeof(psabpf_meter_data_t), ctx->value_size);
        return EINVAL;
    }

    return NO_ERROR;
}

static int check_index(const psabpf_meter_ctx_t *ctx, const psabpf_meter_entry_t *entry) {
    if (entry->index == NULL) {
        fprintf(stderr, "Index is not provided!");
        return EINVAL;
    }

    if (ctx->index_size < entry->index_size) {
        fprintf(stderr, "Provided index(size: %zu) is too big for this meter(index size: %u)\n",
                entry->index_size, ctx->index_size);
        return EINVAL;
    }

    return NO_ERROR;
}

void psabpf_meter_entry_init(psabpf_meter_entry_t *entry) {
    if (entry == NULL)
        return;
    memset(entry, 0, sizeof(psabpf_meter_entry_t));
}

void psabpf_meter_entry_free(psabpf_meter_entry_t *entry) {
    if (entry == NULL)
        return;

    if (entry->index != NULL)
        free(entry->index);
    entry->index = NULL;

    memset(entry, 0, sizeof(psabpf_meter_entry_t));
}

int psabpf_meter_entry_index(psabpf_meter_entry_t *entry, const char *data, size_t size) {
    if (entry == NULL || data == NULL)
        return ENODATA;
    if (entry->index != NULL)
        return EEXIST;

    entry->index = malloc(size);
    memcpy(entry->index, data, size);
    entry->index_size = size;

    return NO_ERROR;
}

int psabpf_meter_entry_data(psabpf_meter_entry_t *entry,
                            psabpf_meter_value_t pir,
                            psabpf_meter_value_t pbs,
                            psabpf_meter_value_t cir,
                            psabpf_meter_value_t cbs) {
    if (entry == NULL)
        return ENODATA;

    entry->pir = pir;
    entry->pbs = pbs;
    entry->cir = cir;
    entry->cbs = cbs;

    return NO_ERROR;
}

void psabpf_meter_ctx_init(psabpf_meter_ctx_t *ctx) {
    memset(ctx, 0, sizeof(psabpf_meter_ctx_t));
}

void psabpf_meter_ctx_free(psabpf_meter_ctx_t *ctx) {
    if (ctx == NULL)
        return;

    memset(ctx, 0, sizeof(psabpf_meter_ctx_t));
}

int psabpf_meter_ctx_name(psabpf_meter_ctx_t *ctx, psabpf_context_t *psabpf_ctx, const char *name) {
    if (ctx == NULL || psabpf_ctx == NULL || name == NULL)
        return EPERM;

    return open_meter(ctx, psabpf_ctx, name);
}

int psabpf_meter_ctx_get(psabpf_meter_ctx_t *ctx, psabpf_meter_entry_t *entry) {
    int return_code = NO_ERROR;
    uint64_t bpf_flags = BPF_F_LOCK;
    char *value_buffer = NULL;
    char *index_buffer = NULL;

    return_code = check_index(ctx, entry);
    if (return_code != NO_ERROR)
        return return_code;

    index_buffer = malloc(ctx->index_size);
    value_buffer = malloc(ctx->value_size);
    if (index_buffer == NULL || value_buffer == NULL) {
        fprintf(stderr, "not enough memory\n");
        return_code = ENOMEM;
        goto clean_up;
    }

    memset(value_buffer, 0, ctx->value_size);
    memset(index_buffer, 0, ctx->index_size);
    memcpy(index_buffer, entry->index, entry->index_size);

    return_code = bpf_map_lookup_elem_flags(ctx->table_fd, index_buffer, value_buffer, bpf_flags);
    if (return_code == -1) {
        return_code = ENOENT;
        fprintf(stderr, "no meter entry\n");
        goto clean_up;
    }
    if (return_code != NO_ERROR) {
        return_code = errno;
        fprintf(stderr, "failed to get meter: %s\n", strerror(errno));
        goto clean_up;
    }
    psabpf_meter_data_t data;
    memcpy(&data, value_buffer, sizeof(data));
    return_code = convert_meter_data_to_entry(&data, entry);

clean_up:
    free(value_buffer);
    free(index_buffer);
    return return_code;
}

int psabpf_meter_ctx_update(psabpf_meter_ctx_t *ctx, psabpf_meter_entry_t *entry) {
    int return_code = NO_ERROR;
    uint64_t bpf_flags = BPF_F_LOCK;
    char *value_buffer = NULL;
    char *index_buffer = NULL;
    psabpf_meter_data_t data;

    return_code = check_index(ctx, entry);
    if (return_code != NO_ERROR)
        return return_code;

    return_code = convert_meter_entry_to_data(entry, &data);
    if (return_code != NO_ERROR)
        return return_code;

    index_buffer = malloc(ctx->index_size);
    value_buffer = malloc(ctx->value_size);
    if (index_buffer == NULL || value_buffer == NULL) {
        fprintf(stderr, "not enough memory\n");
        return_code = ENOMEM;
        goto clean_up;
    }

    memset(value_buffer, 0, ctx->value_size);
    memcpy(value_buffer, &data, sizeof(data));
    memset(index_buffer, 0, ctx->index_size);
    memcpy(index_buffer, entry->index, entry->index_size);

    return_code = bpf_map_update_elem(ctx->table_fd, index_buffer, value_buffer, bpf_flags);
    if (return_code != NO_ERROR) {
        return_code = errno;
        fprintf(stderr, "failed to set up meter: %s\n", strerror(errno));
        goto clean_up;
    }

clean_up:
    free(value_buffer);
    free(index_buffer);
    return return_code;
}

int psabpf_meter_ctx_reset(psabpf_meter_ctx_t *ctx, psabpf_meter_entry_t *entry) {
    int return_code = psabpf_meter_entry_data(entry, 0, 0, 0, 0);
    if (return_code != NO_ERROR)
        return return_code;
    return psabpf_meter_ctx_update(ctx, entry);
}
