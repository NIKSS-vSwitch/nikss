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
#include <string.h>
#include <jansson.h>

#include "register.h"
#include <psabpf.h>

static int parse_dst_register(int *argc, char ***argv, const char **register_name,
                             psabpf_context_t *psabpf_ctx, psabpf_register_context_t *ctx)
{
    if (*argc < 1) {
        fprintf(stderr, "too few parameters\n");
        return EINVAL;
    }

    if (register_name != NULL)
        *register_name = **argv;
    int error_code = psabpf_register_ctx_name(psabpf_ctx, ctx, **argv);
    if (error_code != NO_ERROR)
        return error_code;

    NEXT_ARGP();
    return NO_ERROR;
}

static int parse_register_index(int *argc, char ***argv, psabpf_register_entry_t *entry)
{
    if (!is_keyword(**argv, "index"))
        return NO_ERROR; /* index is optional */
    NEXT_ARGP_RET();

    bool has_any_index = false;
    while (*argc > 0) {
        if (has_any_index) {
            if (is_keyword(**argv, "value"))
                return NO_ERROR;
        }

        int err = translate_data_to_bytes(**argv, entry, CTX_REGISTER_INDEX);
        if (err != NO_ERROR)
            return err;

        has_any_index = true;
        NEXT_ARGP();
    }

    return NO_ERROR;
}

static int parse_register_value(int *argc, char ***argv, psabpf_register_entry_t *entry)
{
    if (!is_keyword(**argv, "value")) {
        fprintf(stderr, "expected \'value\' keyword\n");
        return EINVAL;
    }
    NEXT_ARGP_RET();

    int ret = ENODATA;
    while (*argc > 0) {
        ret = translate_data_to_bytes(**argv, entry, CTX_REGISTER_DATA);
        if (ret != NO_ERROR)
            return ret;
        NEXT_ARGP();
    }

    return ret;
}

static int build_entry(psabpf_register_context_t *ctx, psabpf_register_entry_t *entry,
                       json_t *json_entry)
{
    json_t *index = json_object();
    json_t *value = json_object();
    if (json_entry == NULL || index == NULL || value == NULL) {
        fprintf(stderr, "failed to prepare register in JSON\n");
        return ENOMEM;
    }

    json_object_set_new(json_entry, "index", index);
    json_object_set_new(json_entry, "value", value);

    int ret = build_struct_json(value, ctx, entry, (get_next_field_func_t) psabpf_register_get_next_value_field);
    if (ret != NO_ERROR) {
        fprintf(stderr, "failed to build register value in JSON\n");
        return EINVAL;
    }

    ret = build_struct_json(index, ctx, entry, (get_next_field_func_t) psabpf_register_get_next_index_field);
    if (ret != NO_ERROR) {
        fprintf(stderr, "failed to build register index in JSON\n");
        return EINVAL;
    }

    return NO_ERROR;
}

static int get_and_print_register_json(psabpf_register_context_t *ctx, psabpf_register_entry_t *entry,
                                       const char *register_name, bool entry_has_index)
{
    int ret = EINVAL;
    json_t *root = json_object();
    json_t *instance_name = json_object();
    json_t *entries = json_array();
    if (root == NULL || instance_name == NULL || entries == NULL) {
        fprintf(stderr, "failed to prepare JSON\n");
        goto clean_up;
    }

    json_object_set(root, register_name, entries);

    if (entry_has_index) {
        if (psabpf_register_get(ctx, entry) != NO_ERROR) {
            goto clean_up;
        }
        json_t *json_entry = json_object();
        ret = build_entry(ctx, entry, json_entry);
        json_array_append_new(entries, json_entry);
    } else {
        psabpf_register_entry_t *iter;
        while ((iter = psabpf_register_get_next(ctx)) != NULL) {
            json_t *json_entry = json_object();
            ret = build_entry(ctx, iter, json_entry);
            json_array_append_new(entries, json_entry);
            psabpf_register_entry_free(iter);
            if (ret != NO_ERROR)
                break;
        }
    }

    if (ret != NO_ERROR) {
        fprintf(stderr, "failed to build register JSON: %s\n", strerror(ret));
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

int do_register_get(int argc, char **argv)
{
    int ret = EINVAL;
    const char *register_name = NULL;
    psabpf_context_t psabpf_ctx;
    psabpf_register_context_t ctx;
    psabpf_register_entry_t entry;

    psabpf_context_init(&psabpf_ctx);
    psabpf_register_ctx_init(&ctx);
    psabpf_register_entry_init(&entry);

    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR)
        goto clean_up;

    if (parse_dst_register(&argc, &argv, &register_name, &psabpf_ctx, &ctx) != NO_ERROR)
        goto clean_up;

    bool register_index_provided = (argc >= 1 && is_keyword(*argv, "index"));
    if (register_index_provided) {
        if (parse_register_index(&argc, &argv, &entry) != NO_ERROR)
            goto clean_up;
    }

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    ret = get_and_print_register_json(&ctx, &entry, register_name, register_index_provided);

clean_up:
    psabpf_register_entry_free(&entry);
    psabpf_register_ctx_free(&ctx);
    psabpf_context_free(&psabpf_ctx);

    return ret;
}

int do_register_set(int argc, char **argv) {
    int ret = EINVAL;
    const char *register_name = NULL;
    psabpf_context_t psabpf_ctx;
    psabpf_register_context_t ctx;
    psabpf_register_entry_t entry;

    psabpf_context_init(&psabpf_ctx);
    psabpf_register_ctx_init(&ctx);
    psabpf_register_entry_init(&entry);

    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR)
        goto clean_up;

    if (parse_dst_register(&argc, &argv, &register_name, &psabpf_ctx, &ctx) != NO_ERROR)
        goto clean_up;

    if (parse_register_index(&argc, &argv, &entry) != NO_ERROR)
        goto clean_up;

    if (parse_register_value(&argc, &argv, &entry) != NO_ERROR)
        goto clean_up;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    ret = psabpf_register_set(&ctx, &entry);

clean_up:
    psabpf_register_entry_free(&entry);
    psabpf_register_ctx_free(&ctx);
    psabpf_context_free(&psabpf_ctx);

    return ret;
}

int do_register_help(int argc, char **argv)
{
    (void) argc; (void) argv;
    fprintf(stderr,
            "Usage: %1$s register get pipe ID REGISTER_NAME [index DATA]\n"
            "       %1$s register set pipe ID REGISTER_NAME index DATA value REGISTER_VALUE\n"
            "\n"
            "       REGISTER_VALUE := { DATA }\n"
            "",
            program_name);

    return NO_ERROR;
}
