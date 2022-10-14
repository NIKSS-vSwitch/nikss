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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <psabpf.h>

void psabpf_direct_meter_ctx_init(psabpf_direct_meter_context_t *dm_ctx)
{
    if (dm_ctx == NULL) {
        return;
    }
    memset(dm_ctx, 0, sizeof(psabpf_direct_meter_context_t));
    dm_ctx->mem_can_be_freed = true;
}

void psabpf_direct_meter_ctx_free(psabpf_direct_meter_context_t *dm_ctx)
{
    if (dm_ctx == NULL) {
        return;
    }

    if (dm_ctx->name != NULL && dm_ctx->mem_can_be_freed == true) {
        free((void *) dm_ctx->name);
    }
    dm_ctx->name = NULL;
}

int psabpf_direct_meter_ctx_name(psabpf_direct_meter_context_t *dm_ctx,
                                 psabpf_table_entry_ctx_t *table_ctx, const char *dm_name)
{
    if (dm_ctx == NULL || table_ctx == NULL || dm_name == NULL) {
        return EINVAL;
    }

    for (unsigned i = 0; i < table_ctx->n_direct_meters; i++) {
        if (strcmp(table_ctx->direct_meters_ctx[i].name, dm_name) == 0) {
            dm_ctx->meter_offset = table_ctx->direct_meters_ctx[i].meter_offset;
            dm_ctx->meter_size = table_ctx->direct_meters_ctx[i].meter_size;
            dm_ctx->meter_idx = i;
            return NO_ERROR;
        }
    }

    fprintf(stderr, "%s: DirectMeter entry not found\n", dm_name);
    return ENOENT;
}

int psabpf_table_entry_set_direct_meter(psabpf_table_entry_t *entry, psabpf_direct_meter_context_t *dm_ctx,
                                        psabpf_meter_entry_t *dm)
{
    if (entry == NULL || dm_ctx == NULL || dm == NULL) {
        return EINVAL;
    }

    void *tmp_ptr = NULL;
    if (entry->direct_meters == NULL) {
        tmp_ptr = malloc(sizeof(psabpf_direct_meter_entry_t));
    } else {
        tmp_ptr = realloc(entry->direct_meters, (entry->n_direct_meters + 1) * sizeof(psabpf_direct_meter_entry_t));
    }
    if (tmp_ptr == NULL) {
        fprintf(stderr, "not enough memory\n");
        return ENOMEM;
    }
    entry->direct_meters = tmp_ptr;
    entry->n_direct_meters += 1;

    unsigned idx = entry->n_direct_meters - 1;
    psabpf_meter_entry_init(&entry->direct_meters[idx].meter);
    entry->direct_meters[idx].meter.cbs = dm->cbs;
    entry->direct_meters[idx].meter.pbs = dm->pbs;
    entry->direct_meters[idx].meter.cir = dm->cir;
    entry->direct_meters[idx].meter.pir = dm->pir;
    entry->direct_meters[idx].meter_idx = dm_ctx->meter_idx;

    return NO_ERROR;
}

psabpf_direct_meter_context_t *psabpf_direct_meter_get_next_ctx(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    if (ctx == NULL || entry == NULL) {
        return NULL;
    }

    if (entry->current_direct_meter_ctx_id >= ctx->n_direct_meters) {
        entry->current_direct_meter_ctx_id = 0;
        return NULL;
    }

    memcpy(&entry->current_direct_meter_ctx,
           &ctx->direct_meters_ctx[entry->current_direct_meter_ctx_id],
           sizeof(psabpf_direct_meter_context_t));
    entry->current_direct_meter_ctx.mem_can_be_freed = false;

    entry->current_direct_meter_ctx_id += 1;

    return &entry->current_direct_meter_ctx;
}

const char *psabpf_direct_meter_get_name(psabpf_direct_meter_context_t *dm_ctx)
{
    if (dm_ctx == NULL) {
        return NULL;
    }
    return dm_ctx->name;
}

int psabpf_direct_meter_get_entry(psabpf_direct_meter_context_t *dm_ctx, psabpf_table_entry_t *entry, psabpf_meter_entry_t *dm)
{
    if (dm_ctx == NULL || entry == NULL || dm == NULL) {
        return EINVAL;
    }
    psabpf_meter_entry_init(dm);

    for (unsigned i = 0; i < entry->n_direct_meters; i++) {
        if (dm_ctx->meter_idx == entry->direct_meters[i].meter_idx) {
            memcpy(dm, &entry->direct_meters[i].meter, sizeof(psabpf_meter_entry_t));
            return NO_ERROR;
        }
    }

    return ENOENT;
}
