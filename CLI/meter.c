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

#include <jansson.h>

#include <psabpf.h>

#include "meter.h"

/******************************************************************************
 * Command line parsing functions
 *****************************************************************************/

int convert_str_to_meter_value(const char *str, psabpf_meter_value_t *value)
{
    char * end_ptr = NULL;
    *value = strtoull(str, &end_ptr, 0);
    if (*end_ptr != '\0') {
        fprintf(stderr, "%s: failed to parse value\n", str);
        return EINVAL;
    }
    return NO_ERROR;
}

int parse_dst_meter(int *argc, char ***argv, psabpf_context_t *psabpf_ctx,
                    psabpf_meter_ctx_t *ctx, const char **instance_name)
{
    int error_code = psabpf_meter_ctx_name(ctx, psabpf_ctx, **argv);
    if (error_code != NO_ERROR) {
        return error_code;
    }

    if (instance_name != NULL) {
        *instance_name = **argv;
    }

    NEXT_ARGP();

    return NO_ERROR;
}

int parse_meter_index(int *argc, char ***argv, psabpf_meter_entry_t *entry)
{
    if (!is_keyword(**argv, "index")) {
        return EPERM;
    }

    NEXT_ARGP_RET();

    while (*argc > 0) {
        int error_code = translate_data_to_bytes(**argv, entry, CTX_METER_INDEX);
        if (error_code != NO_ERROR) {
            return error_code;
        }

        if (*argc > 1 && strstr(*(*argv + 1), ":") != NULL) {
            break;
        }

        NEXT_ARGP();
    }

    return NO_ERROR;
}

int parse_meter_data(int *argc, char ***argv, psabpf_meter_entry_t *entry)
{
    NEXT_ARGP_RET();

    int error_code = NO_ERROR;
    char *delimiter = ":";
    char *pir_str = strsep(*argv, delimiter);
    char *pbs_str = strsep(*argv, delimiter);
    if (pbs_str == NULL) {
        fprintf(stderr, "%s: invalid format. Use PIR:PBS\n", pir_str);
        return EINVAL;
    }

    NEXT_ARGP_RET();

    char *cir_str = strsep(*argv, delimiter);
    char *cbs_str = strsep(*argv, delimiter);
    if (cbs_str == NULL) {
        fprintf(stderr, "%s: invalid format. Use CIR:CBS\n", cir_str);
        return EINVAL;
    }

    psabpf_meter_value_t pir;
    error_code = convert_str_to_meter_value(pir_str, &pir);
    if (error_code != NO_ERROR) {
        return error_code;
    }

    psabpf_meter_value_t pbs;
    error_code = convert_str_to_meter_value(pbs_str, &pbs);
    if (error_code != NO_ERROR) {
        return error_code;
    }

    psabpf_meter_value_t cir;
    error_code = convert_str_to_meter_value(cir_str, &cir);
    if (error_code != NO_ERROR) {
        return error_code;
    }

    psabpf_meter_value_t cbs;
    error_code = convert_str_to_meter_value(cbs_str, &cbs);
    if (error_code != NO_ERROR) {
        return error_code;
    }

    return psabpf_meter_entry_data(entry, pir, pbs, cir, cbs);
}

/******************************************************************************
 * JSON functions
 *****************************************************************************/

void *create_json_meter_config(psabpf_meter_entry_t *meter)
{
    json_t *meter_config = json_object();
    if (meter_config == NULL) {
        return NULL;
    }

    psabpf_meter_value_t pir, cir, pbs, cbs;
    psabpf_meter_entry_get_data(meter, &pir, &pbs, &cir, &cbs);
    /* json_int_t is signed type, so if we expect values larger than 2^63
     * they should be converted to string in such case */
    json_object_set_new(meter_config, "pir", json_integer((json_int_t) pir));
    json_object_set_new(meter_config, "pbs", json_integer((json_int_t) pbs));
    json_object_set_new(meter_config, "cir", json_integer((json_int_t) cir));
    json_object_set_new(meter_config, "cbs", json_integer((json_int_t) cbs));

    return meter_config;
}

json_t *create_json_meter_index(psabpf_meter_ctx_t *ctx, psabpf_meter_entry_t *meter)
{
    json_t *index_root = json_object();

    int ret = build_struct_json(index_root, ctx, meter, (get_next_field_func_t) psabpf_meter_entry_get_next_index_field);
    if (ret != NO_ERROR) {
        json_decref(index_root);
        return NULL;
    }

    return index_root;
}

json_t *create_json_meter_entry(psabpf_meter_ctx_t *ctx, psabpf_meter_entry_t *meter)
{
    json_t *entry_root = json_object();
    json_t *meter_config = create_json_meter_config(meter);
    json_t *meter_index = create_json_meter_index(ctx, meter);

    if (entry_root == NULL || meter_config == NULL || meter_index == NULL) {
        fprintf(stderr, "failed to build JSON meter entry\n");
        json_decref(entry_root);
        json_decref(meter_config);
        json_decref(meter_index);
        return NULL;
    }

    json_object_set_new(entry_root, "index", meter_index);
    json_object_set_new(entry_root, "config", meter_config);

    return entry_root;
}

int print_meter(psabpf_meter_ctx_t *ctx, psabpf_meter_entry_t *entry, const char *meter_name)
{
    int ret = EINVAL;
    json_t *root = json_object();
    json_t *instance_name = json_object();
    json_t *entries = json_array();

    if (root == NULL || instance_name == NULL || entries == NULL) {
        fprintf(stderr, "failed to prepare JSON\n");
        ret = ENOMEM;
        goto clean_up;
    }

    if (json_object_set(root, meter_name, instance_name)) {
        fprintf(stderr, "failed to add JSON key %s\n", meter_name);
        goto clean_up;
    }
    json_object_set(instance_name, "entries", entries);

    if (entry != NULL) {
        json_t *parsed_entry = create_json_meter_entry(ctx, entry);
        if (parsed_entry == NULL) {
            fprintf(stderr, "failed to create table JSON entry\n");
            goto clean_up;
        }
        json_array_append_new(entries, parsed_entry);
    } else {
        psabpf_meter_entry_t *current_entry;
        while ((current_entry = psabpf_meter_get_next(ctx)) != NULL) {
            json_t *parsed_entry = create_json_meter_entry(ctx, current_entry);
            if (parsed_entry == NULL) {
                fprintf(stderr, "failed to create table JSON entry\n");
                goto clean_up;
            }
            json_array_append_new(entries, parsed_entry);
            psabpf_meter_entry_free(current_entry);
        }
    }

    json_dumpf(root, stdout, JSON_INDENT(4) | JSON_ENSURE_ASCII);
    ret = NO_ERROR;

clean_up:
    json_decref(instance_name);
    json_decref(entries);
    json_decref(root);

    return ret;
}

/******************************************************************************
 * Command line meter functions
 *****************************************************************************/

int do_meter_get(int argc, char **argv)
{
    psabpf_meter_entry_t entry;
    psabpf_meter_ctx_t meter_ctx;
    psabpf_context_t psabpf_ctx;
    int error_code = EPERM;
    const char *meter_name;

    psabpf_meter_entry_init(&entry);
    psabpf_meter_ctx_init(&meter_ctx);
    psabpf_context_init(&psabpf_ctx);

    /* 0. Get the pipeline id */
    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR) {
        goto clean_up;
    }

    /* 1. Get meter */
    if (parse_dst_meter(&argc, &argv, &psabpf_ctx, &meter_ctx, &meter_name) != NO_ERROR) {
        goto clean_up;
    }

    /* 2. Get index */
    bool index_provided = argc > 0 && is_keyword(*argv, "index");
    if (index_provided) {
        if (parse_meter_index(&argc, &argv, &entry) != NO_ERROR) {
            goto clean_up;
        }
    }

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    /* 3. Get meter value and display it */
    if (index_provided) {
        if (psabpf_meter_entry_get(&meter_ctx, &entry) != NO_ERROR) {
            goto clean_up;
        }

        error_code = print_meter(&meter_ctx, &entry, meter_name);
    } else {
        error_code = print_meter(&meter_ctx, NULL, meter_name);
    }

clean_up:
    psabpf_meter_entry_free(&entry);
    psabpf_meter_ctx_free(&meter_ctx);
    psabpf_context_free(&psabpf_ctx);
    return error_code;
}

int do_meter_update(int argc, char **argv)
{
    psabpf_meter_entry_t entry;
    psabpf_meter_ctx_t meter_ctx;
    psabpf_context_t psabpf_ctx;
    int error_code = EPERM;

    psabpf_meter_entry_init(&entry);
    psabpf_meter_ctx_init(&meter_ctx);
    psabpf_context_init(&psabpf_ctx);

    /* 0. Get the pipeline id */
    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR) {
        goto clean_up;
    }

    /* 1. Get meter */
    if (parse_dst_meter(&argc, &argv, &psabpf_ctx, &meter_ctx, NULL) != NO_ERROR) {
        goto clean_up;
    }

    /* 2. Get index */
    if (parse_meter_index(&argc, &argv, &entry) != NO_ERROR) {
        goto clean_up;
    }

    /* 3. Get meter parameters */
    if (parse_meter_data(&argc, &argv, &entry) != NO_ERROR) {
        goto clean_up;
    }

    NEXT_ARG();

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    error_code = psabpf_meter_entry_update(&meter_ctx, &entry);

clean_up:
    psabpf_meter_entry_free(&entry);
    psabpf_meter_ctx_free(&meter_ctx);
    psabpf_context_free(&psabpf_ctx);
    return error_code;
}

int do_meter_reset(int argc, char **argv)
{
    psabpf_meter_entry_t entry;
    psabpf_meter_ctx_t meter_ctx;
    psabpf_context_t psabpf_ctx;
    int error_code = EPERM;

    psabpf_meter_entry_init(&entry);
    psabpf_meter_ctx_init(&meter_ctx);
    psabpf_context_init(&psabpf_ctx);

    /* 0. Get the pipeline id */
    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR) {
        goto clean_up;
    }

    /* 1. Get meter */
    if (parse_dst_meter(&argc, &argv, &psabpf_ctx, &meter_ctx, NULL) != NO_ERROR) {
        goto clean_up;
    }

    /* 2. Get index */
    bool index_provided = argc > 0 && is_keyword(*argv, "index");
    if (index_provided) {
        if (parse_meter_index(&argc, &argv, &entry) != NO_ERROR) {
            goto clean_up;
        }
    }

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    error_code = psabpf_meter_entry_reset(&meter_ctx, &entry);

clean_up:
    psabpf_meter_entry_free(&entry);
    psabpf_meter_ctx_free(&meter_ctx);
    psabpf_context_free(&psabpf_ctx);
    return error_code;
}

int do_meter_help(int argc, char **argv)
{
    (void) argc; (void) argv;

    fprintf(stderr,
            "Usage: %1$s meter get pipe ID METER_NAME [index INDEX]\n"
            "       %1$s meter update pipe ID METER_NAME index INDEX PIR:PBS CIR:CBS\n"
            "       %1$s meter reset pipe ID METER_NAME [index INDEX]\n"
            "\n"
            "       INDEX := { DATA }\n"
            "       PIR := { DATA }\n"
            "       PBS := { DATA }\n"
            "       CIR := { DATA }\n"
            "       CBS := { DATA }\n"
            "",
            program_name);
    return 0;
}