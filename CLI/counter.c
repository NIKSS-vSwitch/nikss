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

#include <jansson.h>

#include "counter.h"
#include <psabpf.h>

void dump_counter_entry(psabpf_counter_context_t *ctx, psabpf_counter_entry_t *entry)
{
    psabpf_struct_field_t *key;

    printf("counter:\n");
    printf("\ttype: %u\n", psabpf_counter_get_type(ctx));
    printf("\tkey:\n");
    while ((key = psabpf_counter_entry_get_next_key(ctx, entry)) != NULL) {
        const char *name = psabpf_struct_get_field_name(key);
        char *data = convert_bin_data_to_hexstr(psabpf_struct_get_field_data(key), psabpf_struct_get_field_data_len(key));
        if (data == NULL)
            continue;

        printf("\t\t%s: %s\n", name, data);

        free(data);
    }
    printf("\tdata:\n");
    printf("\t\tbytes: %lu\n", psabpf_counter_entry_get_bytes(entry));
    printf("\t\tpackets: %lu\n", psabpf_counter_entry_get_packets(entry));
}

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

//    uint32_t key = 1;
//    psabpf_counter_entry_set_key(&entry, &key, sizeof(key));
//    psabpf_counter_get(&ctx, &entry);
//    dump_counter_entry(&ctx, &entry);

    psabpf_counter_entry_t *iter;
    while ((iter = psabpf_counter_get_next(&ctx)) != NULL) {
        dump_counter_entry(&ctx, iter);

        psabpf_counter_entry_free(iter);
    }

    psabpf_counter_entry_free(&entry);
    psabpf_counter_ctx_free(&ctx);

    psabpf_context_free(&psabpf_ctx);

    return NO_ERROR;
}

int do_counter_set(int argc, char **argv)
{
    (void) argc; (void) argv;
    return NO_ERROR;
}

int do_counter_reset(int argc, char **argv)
{
    (void) argc; (void) argv;
    return NO_ERROR;
}

int do_counter_help(int argc, char **argv)
{
    (void) argc; (void) argv;
    fprintf(stderr,
            "Usage: %1$s counter get pipe ID COUNTER [key DATA]\n"
            "       %1$s counter set pipe ID COUNTER [key DATA] value COUNTER_VALUE\n"
            "       %1$s counter reset pipe ID COUNTER [key DATA]\n"
            "\n"
            "       COUNTER := { id COUNTER_ID | name COUNTER | COUNTER_FILE }\n"
            "       COUNTER_VALUE := { BYTES | PACKETS | BYTES:PACKETS }\n"
            "",
            program_name);

    return NO_ERROR;
}
