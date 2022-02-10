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

#include "counter.h"

int do_counter_get(int argc, char **argv)
{
    (void) argc; (void) argv;

    psabpf_context_t psabpf_ctx;
    psabpf_context_init(&psabpf_ctx);
    psabpf_context_set_pipeline(&psabpf_ctx, 1);

    psabpf_counter_context_t ctx;
    psabpf_counter_ctx_init(&ctx);
    psabpf_counter_open(&psabpf_ctx, &ctx, "ingress_cnt");

    psabpf_counter_entry_t entry;
    psabpf_counter_entry_init(&entry);

    uint32_t key = 1;
    psabpf_counter_entry_set_key(&entry, &key, sizeof(key));
    psabpf_counter_get(&ctx, &entry);

    printf("packets: %lu, bytes: %lu\n", entry.packets, entry.bytes);

    psabpf_counter_entry_free(&entry);
    psabpf_counter_ctx_free(&ctx);

    psabpf_context_free(&psabpf_ctx);

    return NO_ERROR;
}

int do_counter_help(int argc, char **argv)
{
    (void) argc; (void) argv;
    return NO_ERROR;
}
