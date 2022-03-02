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

#include "counter.h"
#include <psabpf.h>

static int parse_dst_counter(int *argc, char ***argv, const char **counter_name,
                             psabpf_context_t *psabpf_ctx, psabpf_counter_context_t *ctx)
{
    if (*argc < 1) {
        fprintf(stderr, "too few parameters\n");
        return EINVAL;
    }

    if (is_keyword(**argv, "id")) {
        NEXT_ARGP_RET();
        fprintf(stderr, "id: counter access not supported\n");
        return ENOTSUP;
    } else if (is_keyword(**argv, "name")) {
        NEXT_ARGP_RET();
        fprintf(stderr, "name: counter access not supported yet\n");
        return ENOTSUP;
    } else {
        if (counter_name != NULL)
            *counter_name = **argv;
        int error_code = psabpf_counter_ctx_name(psabpf_ctx, ctx, **argv);
        if (error_code != NO_ERROR)
            return error_code;
    }

    NEXT_ARGP();
    return NO_ERROR;
}

static int parse_counter_key(int *argc, char ***argv, psabpf_counter_entry_t *entry)
{
    if (!is_keyword(**argv, "key"))
        return NO_ERROR; /* key is optional */
    NEXT_ARGP_RET();

    bool has_any_key = false;
    while (*argc > 0) {
        if (has_any_key) {
            if (is_keyword(**argv, "value"))
                return NO_ERROR;
        }

        int err = translate_data_to_bytes(**argv, entry, CTX_COUNTER_KEY);
        if (err != NO_ERROR)
            return err;

        has_any_key = true;
        NEXT_ARGP();
    }

    return NO_ERROR;
}

int parse_counter_value_str(const char *str, psabpf_counter_type_t type, psabpf_counter_entry_t *entry)
{
    char *end_ptr = NULL;

    psabpf_counter_value_t parsed_value = strtoull(str, &end_ptr, 0);
    if (type == PSABPF_COUNTER_TYPE_BYTES) {
        if (*end_ptr == '\0')
            psabpf_counter_entry_set_bytes(entry, parsed_value);
    } else if (type == PSABPF_COUNTER_TYPE_PACKETS) {
        if (*end_ptr == '\0')
            psabpf_counter_entry_set_packets(entry, parsed_value);
    } else if (type == PSABPF_COUNTER_TYPE_BYTES_AND_PACKETS) {
        if (*end_ptr == ':') {
            psabpf_counter_entry_set_bytes(entry, parsed_value);
            ++end_ptr;
            parsed_value = strtoull(end_ptr, &end_ptr, 0);
            if (*end_ptr == '\0')
                psabpf_counter_entry_set_packets(entry, parsed_value);
        }
    } else {
        fprintf(stderr, "unknown Counter type\n");
        return EBADF;
    }

    if (*end_ptr != '\0') {
        fprintf(stderr, "%s: failed to parse\n", str);
        return EINVAL;
    }

    return NO_ERROR;
}

static int parse_counter_value(int *argc, char ***argv,
                               psabpf_counter_context_t *ctx, psabpf_counter_entry_t *entry)
{
    if (!is_keyword(**argv, "value")) {
        fprintf(stderr, "expected \'value\' keyword\n");
        return EINVAL;
    }
    NEXT_ARGP_RET();

    psabpf_counter_type_t type = psabpf_counter_get_type(ctx);
    int ret = parse_counter_value_str(**argv, type, entry);
    NEXT_ARGP();

    return ret;
}

static int build_json_counter_key(json_t *parent, psabpf_counter_context_t *ctx, psabpf_counter_entry_t *entry)
{
    psabpf_struct_field_t *key;
    while ((key = psabpf_counter_entry_get_next_key(ctx, entry)) != NULL) {
        if (psabpf_struct_get_field_type(key) == PSABPF_STRUCT_FIELD_TYPE_STRUCT_START) {
            json_t *sub_struct = json_object();
            if (sub_struct == NULL)
                return ENOMEM;
            if (json_object_set(parent, psabpf_struct_get_field_name(key), sub_struct)) {
                json_decref(sub_struct);
                return EPERM;
            }

            int ret = build_json_counter_key(sub_struct, ctx, entry);
            json_decref(sub_struct);
            if (ret != NO_ERROR)
                return ret;

            continue;
        }

        if (psabpf_struct_get_field_type(key) == PSABPF_STRUCT_FIELD_TYPE_STRUCT_END)
            return NO_ERROR;

        if (psabpf_struct_get_field_type(key) != PSABPF_STRUCT_FIELD_TYPE_DATA)
            continue;

        const char *field_name = psabpf_struct_get_field_name(key);
        if (field_name == NULL)
            continue;
        char *data = convert_bin_data_to_hexstr(psabpf_struct_get_field_data(key), psabpf_struct_get_field_data_len(key));
        if (data == NULL)
            continue;

        json_object_set_new(parent, field_name, json_string(data));
        free(data);
    }

    return NO_ERROR;
}

static int build_json_counter_entry(json_t *parent, psabpf_counter_context_t *ctx, psabpf_counter_entry_t *entry)
{
    if (parent == NULL)
        return ENOMEM;

    json_t *json_key = json_object();
    if (json_key == NULL)
        return ENOMEM;
    json_object_set(parent, "key", json_key);

    if (build_json_counter_key(json_key, ctx, entry) != NO_ERROR) {
        json_decref(json_key);
        return ENOMEM;
    }
    json_decref(json_key);

    psabpf_counter_type_t type = psabpf_counter_get_type(ctx);
    json_t *json_value = json_object();
    if (json_value == NULL)
        return ENOMEM;
    json_object_set(parent, "value", json_value);

    /* For counter values we cannot use built-in JSON integer type because
     * it is signed type, but we need unsigned one.*/
    if (type == PSABPF_COUNTER_TYPE_BYTES || type == PSABPF_COUNTER_TYPE_BYTES_AND_PACKETS) {
        psabpf_counter_value_t bytes_value = psabpf_counter_entry_get_bytes(entry);
        char *bytes_str = convert_bin_data_to_hexstr(&bytes_value, sizeof(psabpf_counter_value_t));
        if (bytes_str != NULL) {
            json_object_set_new(json_value, "bytes", json_string(bytes_str));
            free(bytes_str);
        } else {
            json_decref(json_value);
            return ENOMEM;
        }
    }
    if (type == PSABPF_COUNTER_TYPE_PACKETS || type == PSABPF_COUNTER_TYPE_BYTES_AND_PACKETS) {
        psabpf_counter_value_t packets_value = psabpf_counter_entry_get_packets(entry);
        char *packets_str = convert_bin_data_to_hexstr(&packets_value, sizeof(psabpf_counter_value_t));
        if (packets_str != NULL) {
            json_object_set_new(json_value, "packets", json_string(packets_str));
            free(packets_str);
        } else{
            json_decref(json_value);
            return ENOMEM;
        }
    }

    json_decref(json_value);
    return NO_ERROR;
}

static int print_json_counter(psabpf_counter_context_t *ctx, psabpf_counter_entry_t *entry,
                              const char *counter_name, bool entry_has_key)
{
    int ret = EINVAL;
    json_t *root = json_object();
    json_t *extern_type = json_object();
    json_t *instance_name = json_object();
    json_t *entries = json_array();

    if (root == NULL || extern_type == NULL || instance_name == NULL || entries == NULL) {
        fprintf(stderr, "failed to prepare JSON\n");
        ret = ENOMEM;
        goto clean_up;
    }

    json_object_set(instance_name, "entries", entries);
    if (json_object_set(extern_type, counter_name, instance_name)) {
        fprintf(stderr, "failed to add JSON key %s\n", counter_name);
        goto clean_up;
    }
    json_object_set(root, "Counter", extern_type);

    psabpf_counter_type_t type = psabpf_counter_get_type(ctx);
    if (type == PSABPF_COUNTER_TYPE_BYTES)
        json_object_set_new(instance_name, "type", json_string("BYTES"));
    else if (type == PSABPF_COUNTER_TYPE_PACKETS)
        json_object_set_new(instance_name, "type", json_string("PACKETS"));
    else if (type == PSABPF_COUNTER_TYPE_BYTES_AND_PACKETS)
        json_object_set_new(instance_name, "type", json_string("PACKETS_AND_BYTES"));
    else
        json_object_set_new(instance_name, "type", json_string("UNKNOWN"));

    if (entry_has_key) {
        if ((ret = psabpf_counter_get(ctx, entry)) != NO_ERROR)
            goto clean_up;
        json_t *current_obj = json_object();
        ret = build_json_counter_entry(current_obj, ctx, entry);
        json_array_append_new(entries, current_obj);
    } else {
        psabpf_counter_entry_t *iter;
        while ((iter = psabpf_counter_get_next(ctx)) != NULL) {
            json_t *current_obj = json_object();
            ret = build_json_counter_entry(current_obj, ctx, iter);
            json_array_append_new(entries, current_obj);
            psabpf_counter_entry_free(iter);
            if (ret != NO_ERROR)
                break;
        }
    }

    if (ret != NO_ERROR) {
        fprintf(stderr, "failed to build JSON: %s\n", strerror(ret));
        goto clean_up;
    }

    json_dumpf(root, stdout, JSON_INDENT(4) | JSON_ENSURE_ASCII);

    ret = NO_ERROR;

clean_up:
    json_decref(extern_type);
    json_decref(instance_name);
    json_decref(entries);
    json_decref(root);

    return ret;
}

int do_counter_get(int argc, char **argv)
{
    int ret = EINVAL;
    const char *counter_name = NULL;
    psabpf_context_t psabpf_ctx;
    psabpf_counter_context_t ctx;
    psabpf_counter_entry_t entry;

    psabpf_context_init(&psabpf_ctx);
    psabpf_counter_ctx_init(&ctx);
    psabpf_counter_entry_init(&entry);

    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR)
        goto clean_up;

    if (parse_dst_counter(&argc, &argv, &counter_name, &psabpf_ctx, &ctx) != NO_ERROR)
        goto clean_up;

    bool counter_key_provided = (argc >= 1 && is_keyword(*argv, "key"));
    if (counter_key_provided) {
        if (parse_counter_key(&argc, &argv, &entry) != NO_ERROR)
            goto clean_up;
    }

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    ret = print_json_counter(&ctx, &entry, counter_name, counter_key_provided);

clean_up:
    psabpf_counter_entry_free(&entry);
    psabpf_counter_ctx_free(&ctx);
    psabpf_context_free(&psabpf_ctx);

    return ret;
}

int do_counter_set(int argc, char **argv)
{
    int ret = EINVAL;
    psabpf_context_t psabpf_ctx;
    psabpf_counter_context_t ctx;
    psabpf_counter_entry_t entry;

    psabpf_context_init(&psabpf_ctx);
    psabpf_counter_ctx_init(&ctx);
    psabpf_counter_entry_init(&entry);

    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR)
        goto clean_up;

    if (parse_dst_counter(&argc, &argv, NULL, &psabpf_ctx, &ctx) != NO_ERROR)
        goto clean_up;

    if (parse_counter_key(&argc, &argv, &entry) != NO_ERROR)
        goto clean_up;

    if (parse_counter_value(&argc, &argv, &ctx, &entry) != NO_ERROR)
        goto clean_up;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    ret = psabpf_counter_set(&ctx, &entry);

clean_up:
    psabpf_counter_entry_free(&entry);
    psabpf_counter_ctx_free(&ctx);
    psabpf_context_free(&psabpf_ctx);

    return ret;
}

int do_counter_reset(int argc, char **argv)
{
    int ret = EINVAL;
    psabpf_context_t psabpf_ctx;
    psabpf_counter_context_t ctx;
    psabpf_counter_entry_t entry;

    psabpf_context_init(&psabpf_ctx);
    psabpf_counter_ctx_init(&ctx);
    psabpf_counter_entry_init(&entry);

    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR)
        goto clean_up;

    if (parse_dst_counter(&argc, &argv, NULL, &psabpf_ctx, &ctx) != NO_ERROR)
        goto clean_up;

    if (parse_counter_key(&argc, &argv, &entry) != NO_ERROR)
        goto clean_up;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    ret = psabpf_counter_reset(&ctx, &entry);

clean_up:
    psabpf_counter_entry_free(&entry);
    psabpf_counter_ctx_free(&ctx);
    psabpf_context_free(&psabpf_ctx);

    return ret;
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
