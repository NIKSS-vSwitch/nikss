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

void psabpf_direct_counter_ctx_init(psabpf_direct_counter_context_t *dc_ctx)
{
    if (dc_ctx == NULL)
        return;

    memset(dc_ctx, 0, sizeof(psabpf_direct_counter_context_t));
    dc_ctx->counter_idx = -1;
}

void psabpf_direct_counter_ctx_free(psabpf_direct_counter_context_t *dc_ctx)
{
    if (dc_ctx == NULL)
        return;

    if (dc_ctx->name != NULL)
        free((void *) dc_ctx->name);
    dc_ctx->name = NULL;
}

int psabpf_direct_counter_ctx_name(psabpf_direct_counter_context_t *dc_ctx,
                                   psabpf_table_entry_ctx_t *table_ctx, const char *dc_name)
{
    if (dc_ctx == NULL || table_ctx == NULL || dc_name == NULL)
        return EINVAL;

    for (unsigned i = 0; i < table_ctx->n_direct_counters; i++) {
        if (strcmp(table_ctx->direct_counters_ctx[i].name, dc_name) == 0) {
            dc_ctx->counter_type = table_ctx->direct_counters_ctx[i].counter_type;
            dc_ctx->counter_offset = table_ctx->direct_counters_ctx[i].counter_offset;
            dc_ctx->counter_size = table_ctx->direct_counters_ctx[i].counter_size;
            dc_ctx->counter_idx = i;
            return NO_ERROR;
        }
    }

    fprintf(stderr, "%s: DirectCounter entry not found\n", dc_name);
    return ENOENT;
}

int psabpf_table_entry_set_direct_counter(psabpf_table_entry_t *entry,
                                          psabpf_direct_counter_context_t *dc_ctx, psabpf_counter_entry_t *dc)
{
    if (entry == NULL || dc_ctx == NULL || dc == NULL)
        return EINVAL;

    void *tmp_ptr = NULL;
    if (entry->direct_counters == NULL)
        tmp_ptr = malloc(sizeof(psabpf_direct_counter_entry_t));
    else
        tmp_ptr = realloc(entry->direct_counters, (entry->n_direct_counters + 1) * sizeof(psabpf_direct_counter_entry_t));
    if (tmp_ptr == NULL) {
        fprintf(stderr, "not enough memory\n");
        return ENOMEM;
    }
    entry->direct_counters = tmp_ptr;
    entry->n_direct_counters += 1;

    unsigned idx = entry->n_direct_counters - 1;
    psabpf_counter_entry_init(&entry->direct_counters[idx].counter);
    entry->direct_counters[idx].counter.bytes = dc->bytes;
    entry->direct_counters[idx].counter.packets = dc->packets;
    entry->direct_counters[idx].counter_idx = dc_ctx->counter_idx;

    return NO_ERROR;
}

psabpf_counter_type_t psabpf_direct_counter_get_type(psabpf_direct_counter_context_t *dc_ctx)
{
    if (dc_ctx == NULL)
        return PSABPF_COUNTER_TYPE_UNKNOWN;
    return dc_ctx->counter_type;
}
