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
#include <string.h>
#include <errno.h>

#include <jansson.h>

#include <psabpf_digest.h>
#include "digest.h"

static int parse_digest(int *argc, char ***argv, psabpf_context_t *psabpf_ctx,
                        psabpf_digest_context_t *ctx, const char **instance_name)
{
    if (*argc < 1) {
        fprintf(stderr, "too few parameters\n");
        return EPERM;
    }
    if (is_keyword(**argv, "id")) {
        NEXT_ARGP_RET();
        fprintf(stderr, "id: digest access not supported\n");
        return ENOTSUP;
    } else if (is_keyword(**argv, "name")) {
        NEXT_ARGP_RET();
        fprintf(stderr, "name: digest access not supported yet\n");
        return ENOTSUP;
    } else {
        int error_code = psabpf_digest_open(psabpf_ctx, ctx, **argv);
        if (error_code != NO_ERROR) {
            fprintf(stderr, "failed to open digest %s: %s\n", **argv, strerror(error_code));
            return error_code;
        }
        *instance_name = **argv;
    }
    NEXT_ARGP();

    return NO_ERROR;
}

static int build_struct_json(json_t *parent, psabpf_digest_context_t *ctx, psabpf_digest_t *digest)
{
    psabpf_struct_field_t *field;
    while ((field = psabpf_digest_get_next_field(ctx, digest)) != NULL) {
        /* To build flat structure of output JSON just remove this and next conditional
         * statement. In other words, preserve only condition and instructions below it:
         *      if (psabpf_digest_get_field_type(field) != DIGEST_FIELD_TYPE_DATA) continue; */
        if (psabpf_struct_get_field_type(field) == PSABPF_STRUCT_FIELD_TYPE_STRUCT_START) {
            json_t *sub_struct = json_object();
            if (sub_struct == NULL) {
                fprintf(stderr, "failed to prepare message sub-object JSON\n");
                return ENOMEM;
            }
            if (json_object_set(parent, psabpf_struct_get_field_name(field), sub_struct)) {
                fprintf(stderr, "failed to add message sub-object JSON\n");
                json_decref(sub_struct);
                return EPERM;
            }

            int ret = build_struct_json(sub_struct, ctx, digest);
            json_decref(sub_struct);
            if (ret != NO_ERROR)
                return ret;

            continue;
        }

        if (psabpf_struct_get_field_type(field) == PSABPF_STRUCT_FIELD_TYPE_STRUCT_END)
            return NO_ERROR;

        if (psabpf_struct_get_field_type(field) != PSABPF_STRUCT_FIELD_TYPE_DATA)
            continue;

        const char *encoded_data = convert_bin_data_to_hexstr(psabpf_struct_get_field_data(field),
                                                              psabpf_struct_get_field_data_len(field));
        if (encoded_data == NULL) {
            fprintf(stderr, "not enough memory\n");
            return ENOMEM;
        }
        const char *field_name = psabpf_struct_get_field_name(field);
        if (field_name == NULL)
            field_name = "";
        json_object_set_new(parent, field_name, json_string(encoded_data));
        free((void *) encoded_data);
    }

    return NO_ERROR;
}

int do_digest_get(int argc, char **argv)
{
    psabpf_context_t psabpf_ctx;
    psabpf_digest_context_t ctx;
    int error_code = EPERM;
    const char *digest_instance_name = NULL;

    psabpf_context_init(&psabpf_ctx);
    psabpf_digest_context_init(&ctx);

    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR)
        goto clean_up_psabpf;

    if (parse_digest(&argc, &argv, &psabpf_ctx, &ctx, &digest_instance_name) != NO_ERROR)
        goto clean_up_psabpf;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up_psabpf;
    }

    json_t *root = json_object();
    json_t *extern_type = json_object();
    json_t *instance_name = json_object();
    json_t *entries = json_array();
    if (root == NULL || extern_type == NULL || instance_name == NULL || entries == NULL) {
        fprintf(stderr, "failed to prepare JSON\n");
        goto clean_up;
    }

    json_object_set(instance_name, "digests", entries);
    if (json_object_set(extern_type, digest_instance_name, instance_name)) {
        fprintf(stderr, "failed to add JSON key %s\n", digest_instance_name);
        goto clean_up;
    }
    json_object_set(root, "Digest", extern_type);

    psabpf_digest_t digest;
    while (psabpf_digest_get_next(&ctx, &digest) == NO_ERROR) {
        json_t *entry = json_object();
        if (entry == NULL) {
            fprintf(stderr, "failed to prepare digest message in JSON\n");
            goto clean_up;
        }
        int ret = build_struct_json(entry, &ctx, &digest);
        json_array_append_new(entries, entry);
        psabpf_digest_free(&digest);

        if (ret != NO_ERROR)
            break;
    }

    json_dumpf(root, stdout, JSON_INDENT(4) | JSON_ENSURE_ASCII);

    error_code = 0;

clean_up:
    json_decref(extern_type);
    json_decref(instance_name);
    json_decref(entries);
    json_decref(root);

clean_up_psabpf:
    psabpf_digest_context_free(&ctx);
    psabpf_context_free(&psabpf_ctx);

    return error_code;
}

int do_digest_help(int argc, char **argv)
{
    (void) argc; (void) argv;
    fprintf(stderr,
            "Usage: %1$s digest get pipe ID DIGEST\n"
            "\n"
            "       DIGEST := { id DIGEST_ID | name FILE | DIGEST_FILE }\n"
            "",
            program_name);
    return 0;
}
