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
#include <string.h>

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

    int error_code = psabpf_digest_ctx_name(psabpf_ctx, ctx, **argv);
    if (error_code != NO_ERROR) {
        fprintf(stderr, "failed to open digest %s: %s\n", **argv, strerror(error_code));
        return error_code;
    }
    *instance_name = **argv;

    NEXT_ARGP();

    return NO_ERROR;
}

int get_digests_and_print(int argc, char **argv, bool only_single_entry)
{
    psabpf_context_t psabpf_ctx;
    psabpf_digest_context_t ctx;
    int error_code = EPERM;
    const char *digest_instance_name = NULL;

    psabpf_context_init(&psabpf_ctx);
    psabpf_digest_ctx_init(&ctx);

    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR) {
        goto clean_up_psabpf;
    }

    if (parse_digest(&argc, &argv, &psabpf_ctx, &ctx, &digest_instance_name) != NO_ERROR) {
        goto clean_up_psabpf;
    }

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up_psabpf;
    }

    json_t *root = json_object();
    json_t *instance_name = json_object();
    json_t *entries = json_array();
    if (root == NULL || instance_name == NULL || entries == NULL) {
        fprintf(stderr, "failed to prepare JSON\n");
        goto clean_up;
    }

    json_object_set(instance_name, "digests", entries);
    if (json_object_set(root, digest_instance_name, instance_name)) {
        fprintf(stderr, "failed to add JSON key %s\n", digest_instance_name);
        goto clean_up;
    }

    psabpf_digest_t digest;
    while (psabpf_digest_get_next(&ctx, &digest) == NO_ERROR) {
        json_t *entry = json_object();
        if (entry == NULL) {
            fprintf(stderr, "failed to prepare digest message in JSON\n");
            goto clean_up;
        }
        int ret = build_struct_json(entry, &ctx, &digest, (get_next_field_func_t) psabpf_digest_get_next_field);
        json_array_append_new(entries, entry);
        psabpf_digest_free(&digest);

        if (ret != NO_ERROR) {
            break;
        }

        if (only_single_entry) {
            break;
        }
    }

    json_dumpf(root, stdout, JSON_INDENT(4) | JSON_ENSURE_ASCII);

    error_code = 0;

clean_up:
    json_decref(instance_name);
    json_decref(entries);
    json_decref(root);

clean_up_psabpf:
    psabpf_digest_ctx_free(&ctx);
    psabpf_context_free(&psabpf_ctx);

    return error_code;
}

int do_digest_get(int argc, char **argv)
{
    return get_digests_and_print(argc, argv, true);
}

int do_digest_get_all(int argc, char **argv)
{
    return get_digests_and_print(argc, argv, false);
}

int do_digest_help(int argc, char **argv)
{
    (void) argc; (void) argv;
    fprintf(stderr,
            "Usage: %1$s digest get pipe ID DIGEST_NAME\n"
            "       %1$s digest get-all pipe ID DIGEST_NAME\n",
            program_name);
    return 0;
}
