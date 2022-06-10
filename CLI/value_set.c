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
#include <errno.h>
#include <string.h>
#include <jansson.h>

#include "value_set.h"
#include <psabpf.h>
#include <psabpf_value_set.h>

static int parse_dst_value_set(int *argc, char ***argv, const char **value_set_name,
                               psabpf_context_t *psabpf_ctx, psabpf_value_set_context_t *ctx)
{
    if (*argc < 1) {
        fprintf(stderr, "too few parameters\n");
        return EINVAL;
    }

    if (value_set_name != NULL)
        *value_set_name = **argv;
    int error_code = psabpf_value_set_context_name(psabpf_ctx, ctx, **argv);
    if (error_code != NO_ERROR)
        return error_code;

    NEXT_ARGP();
    return NO_ERROR;
}

static int parse_value_set_value(int *argc, char ***argv, psabpf_table_entry_t *entry)
{
    if (!is_keyword(**argv, "value")) {
        fprintf(stderr, "expected \'value\' keyword\n");
        return EINVAL;
    }

    return parse_key_data(argc, argv, entry);
}

static int get_and_print_value_set_json(psabpf_value_set_context_t *ctx,
                                        const char *value_set_name)
{
    int ret = NO_ERROR;
    json_t *root = json_object();
    json_t *instance_name = json_object();
    json_t *entries = json_array();
    if (root == NULL || instance_name == NULL || entries == NULL) {
        fprintf(stderr, "failed to prepare JSON\n");
        goto clean_up;
    }

    json_object_set(root, value_set_name, entries);

    psabpf_table_entry_ctx_t tec = {
            .table = ctx->set_map,
            .btf_metadata = ctx->btf_metadata,
    };
    psabpf_table_entry_t *current_entry = NULL;
    while ((current_entry = psabpf_table_entry_get_next(&tec)) != NULL) {
        json_t *json_entry = json_object();
        json_t *key = create_json_entry_key(current_entry);
        if (key == NULL) {
            fprintf(stderr, "failed to build value_set value in JSON\n");
            ret = EINVAL;
            break;
        }
        json_object_set_new(json_entry, "value", key);
        json_array_append_new(entries, json_entry);
        psabpf_table_entry_free(current_entry);
    }

    if (ret != NO_ERROR) {
        fprintf(stderr, "failed to build value_set JSON: %s\n", strerror(ret));
        goto clean_up;
    }

    json_dumpf(root, stdout, JSON_INDENT(4) | JSON_ENSURE_ASCII);
    ret = NO_ERROR;

clean_up:
    json_decref(entries);
    json_decref(instance_name);
    json_decref(root);

    return ret;
}

int do_value_set_delete(int argc, char **argv)
{
    int ret = EINVAL;
    const char *value_set_name = NULL;
    psabpf_context_t psabpf_ctx;
    psabpf_value_set_context_t ctx;
    psabpf_table_entry_t entry;

    psabpf_context_init(&psabpf_ctx);
    psabpf_value_set_context_init(&ctx);
    psabpf_table_entry_init(&entry);

    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR)
        goto clean_up;

    if (parse_dst_value_set(&argc, &argv, &value_set_name, &psabpf_ctx, &ctx) != NO_ERROR)
        goto clean_up;

    if (parse_value_set_value(&argc, &argv, &entry) != NO_ERROR)
        goto clean_up;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    ret = psabpf_value_set_delete(&ctx, &entry);

clean_up:
    psabpf_table_entry_free(&entry);
    psabpf_value_set_context_free(&ctx);
    psabpf_context_free(&psabpf_ctx);

    return ret;
}

int do_value_set_insert(int argc, char **argv)
{
    int ret = EINVAL;
    const char *value_set_name = NULL;
    psabpf_context_t psabpf_ctx;
    psabpf_value_set_context_t ctx;
    psabpf_table_entry_t entry;

    psabpf_context_init(&psabpf_ctx);
    psabpf_value_set_context_init(&ctx);
    psabpf_table_entry_init(&entry);

    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR)
        goto clean_up;

    if (parse_dst_value_set(&argc, &argv, &value_set_name, &psabpf_ctx, &ctx) != NO_ERROR)
        goto clean_up;

    if (parse_value_set_value(&argc, &argv, &entry) != NO_ERROR)
        goto clean_up;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    ret = psabpf_value_set_insert(&ctx, &entry);

clean_up:
    psabpf_table_entry_free(&entry);
    psabpf_value_set_context_free(&ctx);
    psabpf_context_free(&psabpf_ctx);

    return ret;
}

int do_value_set_get(int argc, char **argv)
{
    int ret = EINVAL;
    const char *value_set_name = NULL;
    psabpf_context_t psabpf_ctx;
    psabpf_value_set_context_t ctx;
    psabpf_table_entry_t entry;

    psabpf_context_init(&psabpf_ctx);
    psabpf_value_set_context_init(&ctx);
    psabpf_table_entry_init(&entry);

    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR)
        goto clean_up;

    if (parse_dst_value_set(&argc, &argv, &value_set_name, &psabpf_ctx, &ctx) != NO_ERROR)
        goto clean_up;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    ret = get_and_print_value_set_json(&ctx, value_set_name);

clean_up:
    psabpf_table_entry_free(&entry);
    psabpf_value_set_context_free(&ctx);
    psabpf_context_free(&psabpf_ctx);

    return ret;
}

int do_value_set_help(int argc, char **argv)
{
    (void) argc; (void) argv;
    fprintf(stderr,
            "Usage: %1$s value_set get pipe ID VALUE_SET_NAME\n"
            "       %1$s value_set insert pipe ID VALUE_SET_NAME value DATA\n"
            "       %1$s value_set delete pipe ID VALUE_SET_NAME value DATA\n"
            "",
            program_name);

    return NO_ERROR;
}