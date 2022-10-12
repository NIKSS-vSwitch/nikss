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

#include <nikss.h>

void nikss_direct_counter_ctx_init(nikss_direct_counter_context_t *dc_ctx)
{
    if (dc_ctx == NULL) {
        return;
    }

    memset(dc_ctx, 0, sizeof(nikss_direct_counter_context_t));
    dc_ctx->counter_idx = -1;
    dc_ctx->mem_can_be_freed = true;
}

void nikss_direct_counter_ctx_free(nikss_direct_counter_context_t *dc_ctx)
{
    if (dc_ctx == NULL) {
        return;
    }

    if (dc_ctx->name != NULL && dc_ctx->mem_can_be_freed == true) {
        free((void *) dc_ctx->name);
    }
    dc_ctx->name = NULL;
}

int nikss_direct_counter_ctx_name(nikss_direct_counter_context_t *dc_ctx,
                                  nikss_table_entry_ctx_t *table_ctx, const char *dc_name)
{
    if (dc_ctx == NULL || table_ctx == NULL || dc_name == NULL) {
        return EINVAL;
    }

    for (unsigned i = 0; i < table_ctx->n_direct_counters; i++) {
        if (strcmp(table_ctx->direct_counters_ctx[i].name, dc_name) == 0) {
            dc_ctx->counter_type = table_ctx->direct_counters_ctx[i].counter_type;
            dc_ctx->counter_offset = table_ctx->direct_counters_ctx[i].counter_offset;
            dc_ctx->counter_size = table_ctx->direct_counters_ctx[i].counter_size;
            dc_ctx->counter_idx = i;
            dc_ctx->name = table_ctx->direct_counters_ctx[i].name;
            dc_ctx->mem_can_be_freed = false;
            return NO_ERROR;
        }
    }

    fprintf(stderr, "%s: DirectCounter entry not found\n", dc_name);
    return ENOENT;
}

int nikss_table_entry_set_direct_counter(nikss_table_entry_t *entry,
                                         nikss_direct_counter_context_t *dc_ctx, nikss_counter_entry_t *dc)
{
    if (entry == NULL || dc_ctx == NULL || dc == NULL) {
        return EINVAL;
    }

    void *tmp_ptr = NULL;
    if (entry->direct_counters == NULL) {
        tmp_ptr = malloc(sizeof(nikss_direct_counter_entry_t));
    } else {
        tmp_ptr = realloc(entry->direct_counters, (entry->n_direct_counters + 1) * sizeof(nikss_direct_counter_entry_t));
    }
    if (tmp_ptr == NULL) {
        fprintf(stderr, "not enough memory\n");
        return ENOMEM;
    }
    entry->direct_counters = tmp_ptr;
    entry->n_direct_counters += 1;

    unsigned idx = entry->n_direct_counters - 1;
    nikss_counter_entry_init(&entry->direct_counters[idx].counter);
    entry->direct_counters[idx].counter.bytes = dc->bytes;
    entry->direct_counters[idx].counter.packets = dc->packets;
    entry->direct_counters[idx].counter_idx = dc_ctx->counter_idx;

    return NO_ERROR;
}

nikss_direct_counter_context_t *nikss_direct_counter_get_next_ctx(nikss_table_entry_ctx_t *ctx, nikss_table_entry_t *entry)
{
    if (ctx == NULL || entry == NULL) {
        return NULL;
    }

    if (entry->current_direct_counter_ctx_id >= ctx->n_direct_counters) {
        entry->current_direct_counter_ctx_id = 0;
        return NULL;
    }

    memcpy(&entry->current_direct_counter_ctx,
           &ctx->direct_counters_ctx[entry->current_direct_counter_ctx_id],
           sizeof(nikss_direct_counter_context_t));
    entry->current_direct_counter_ctx.mem_can_be_freed = false;

    entry->current_direct_counter_ctx_id += 1;

    return &entry->current_direct_counter_ctx;
}

nikss_counter_type_t nikss_direct_counter_get_type(nikss_direct_counter_context_t *dc_ctx)
{
    if (dc_ctx == NULL) {
        return NIKSS_COUNTER_TYPE_UNKNOWN;
    }
    return dc_ctx->counter_type;
}

const char *nikss_direct_counter_get_name(nikss_direct_counter_context_t *dc_ctx)
{
    if (dc_ctx == NULL) {
        return NULL;
    }
    return dc_ctx->name;
}

int nikss_direct_counter_get_entry(nikss_direct_counter_context_t *dc_ctx, nikss_table_entry_t *entry, nikss_counter_entry_t *dc)
{
    if (dc_ctx == NULL || entry == NULL || dc == NULL) {
        return EINVAL;
    }
    nikss_counter_entry_init(dc);

    for (unsigned i = 0; i < entry->n_direct_counters; i++) {
        if (dc_ctx->counter_idx == entry->direct_counters[i].counter_idx) {
            memcpy(dc, &entry->direct_counters[i].counter, sizeof(nikss_counter_entry_t));
            return NO_ERROR;
        }
    }

    return ENOENT;
}
