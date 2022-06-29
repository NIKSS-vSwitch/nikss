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
#include <stdbool.h>

#include "clone_session.h"
#include <psabpf_pre.h>
#include "common.h"

static int clone_session_create(psabpf_context_t *ctx, psabpf_clone_session_id_t clone_session_id)
{
    int error;
    psabpf_clone_session_ctx_t session;

    psabpf_clone_session_context_init(&session);
    psabpf_clone_session_id(&session, clone_session_id);

    if (psabpf_clone_session_exists(ctx, &session)) {
        fprintf(stderr, "clone session %u already exists\n", clone_session_id);
        error = EEXIST;
        goto err;
    }

    error = psabpf_clone_session_create(ctx, &session);
    if (error)
        goto err;

err:
    psabpf_clone_session_context_free(&session);

    return error;
}

static int clone_session_delete(psabpf_context_t *ctx, psabpf_clone_session_id_t clone_session_id)
{
    int error;
    psabpf_clone_session_ctx_t session;

    psabpf_clone_session_context_init(&session);
    psabpf_clone_session_id(&session, clone_session_id);

    if (!psabpf_clone_session_exists(ctx, &session)) {
        fprintf(stderr, "no such clone session %u\n", clone_session_id);
        error = ENOENT;
        goto err;
    }

    error = psabpf_clone_session_delete(ctx, &session);
    if (error)
        goto err;

err:
    psabpf_clone_session_context_free(&session);

    return error;
}

static int clone_session_add_member(psabpf_context_t *ctx,
                                    psabpf_clone_session_id_t clone_session_id,
                                    uint32_t  egress_port,
                                    uint16_t  instance,
                                    uint8_t   class_of_service,
                                    bool      truncate,
                                    uint16_t  packet_length_bytes)
{
    int error;
    psabpf_clone_session_ctx_t session;
    psabpf_clone_session_entry_t entry;

    psabpf_clone_session_context_init(&session);
    psabpf_clone_session_id(&session, clone_session_id);

    if (!psabpf_clone_session_exists(ctx, &session)) {
        fprintf(stderr, "no such clone session %u\n", clone_session_id);
        error = ENOENT;
        goto err;
    }

    psabpf_clone_session_entry_init(&entry);
    psabpf_clone_session_entry_port(&entry, egress_port);
    psabpf_clone_session_entry_instance(&entry, instance);
    psabpf_clone_session_entry_cos(&entry, class_of_service);

    if (truncate) {
        psabpf_clone_session_entry_truncate_enable(&entry, packet_length_bytes);
    }

    error = psabpf_clone_session_entry_update(ctx, &session, &entry);
    if (error) {
        goto err;
    }

err:
    psabpf_clone_session_context_free(&session);
    psabpf_clone_session_entry_free(&entry);

    return error;
}

static int clone_session_del_member(psabpf_context_t *ctx,
                                    psabpf_clone_session_id_t clone_session_id,
                                    uint32_t  egress_port,
                                    uint16_t  instance)
{
    int error;
    psabpf_clone_session_ctx_t session;
    psabpf_clone_session_entry_t entry;

    psabpf_clone_session_context_init(&session);
    psabpf_clone_session_id(&session, clone_session_id);

    if (!psabpf_clone_session_exists(ctx, &session)) {
        fprintf(stderr, "no such clone session %u\n", clone_session_id);
        error = ENOENT;
        goto err;
    }

    psabpf_clone_session_entry_init(&entry);
    psabpf_clone_session_entry_port(&entry, egress_port);
    psabpf_clone_session_entry_instance(&entry, instance);

    error = psabpf_clone_session_entry_delete(ctx, &session, &entry);
    if (error) {
        goto err;
    }

err:
    psabpf_clone_session_context_free(&session);
    psabpf_clone_session_entry_free(&entry);

    return error;
}

int do_clone_session_create(int argc, char **argv)
{
    psabpf_context_t ctx;
    psabpf_context_init(&ctx);
    int ret = EINVAL;

    if (parse_pipeline_id(&argc, &argv, &ctx) != NO_ERROR)
        goto err;

    uint32_t session_id;
    parser_keyword_value_pair_t kv[] = {
            {"id", &session_id, sizeof(session_id), true, "session id"},
            { 0 },
    };

    if (parse_keyword_value_pairs(&argc, &argv, &kv[0]) != NO_ERROR)
        goto err;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto err;
    }

    ret = clone_session_create(&ctx, session_id);

err:
    psabpf_context_free(&ctx);

    return ret;
}

int do_clone_session_delete(int argc, char **argv)
{
    psabpf_context_t ctx;
    psabpf_context_init(&ctx);
    int ret = EINVAL;

    if (parse_pipeline_id(&argc, &argv, &ctx) != NO_ERROR)
        goto err;

    uint32_t session_id;
    parser_keyword_value_pair_t kv[] = {
            {"id", &session_id, sizeof(session_id), true, "session id"},
            { 0 },
    };

    if (parse_keyword_value_pairs(&argc, &argv, &kv[0]) != NO_ERROR)
        goto err;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto err;
    }

    ret = clone_session_delete(&ctx, session_id);

err:
    psabpf_context_free(&ctx);

    return ret;
}

int do_clone_session_add_member(int argc, char **argv)
{
    psabpf_context_t ctx;
    psabpf_context_init(&ctx);
    int ret = EINVAL;

    if (parse_pipeline_id(&argc, &argv, &ctx) != NO_ERROR)
        goto err;

    uint32_t session_id, egress_port;
    uint16_t instance, plen_bytes;
    uint8_t cos = 0;
    bool truncate = false;
    parser_keyword_value_pair_t kv[] = {
            {"id",          &session_id,  sizeof(session_id),  true,  "session id"},
            {"egress-port", &egress_port, sizeof(egress_port), true,  "egress port"},
            {"instance",    &instance,    sizeof(instance),    true,  "egress port instance"},
            {"cos",         &cos,         sizeof(cos),         false, "class of service"},
            { 0 },
    };
    parser_keyword_value_pair_t truncate_kv[] = {
            {"plen_bytes", &plen_bytes,  sizeof(plen_bytes),  true,  "packet len truncate size"},
            { 0 },
    };

    if (parse_keyword_value_pairs(&argc, &argv, &kv[0]) != NO_ERROR)
        goto err;

    if (is_keyword(*argv, "truncate")) {
        NEXT_ARG();
        truncate = true;
        if (parse_keyword_value_pairs(&argc, &argv, &truncate_kv[0]) != NO_ERROR)
            goto err;
    }

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto err;
    }

    ret = clone_session_add_member(&ctx, session_id, egress_port, instance, cos, truncate, plen_bytes);

err:
    psabpf_context_free(&ctx);

    return ret;
}

int do_clone_session_del_member(int argc, char **argv)
{
    psabpf_context_t ctx;
    psabpf_context_init(&ctx);
    int ret = EINVAL;

    if (parse_pipeline_id(&argc, &argv, &ctx) != NO_ERROR)
        goto err;

    uint32_t session_id, egress_port;
    uint16_t instance;
    parser_keyword_value_pair_t kv[] = {
            {"id",          &session_id,  sizeof(session_id),  true, "session id"},
            {"egress-port", &egress_port, sizeof(egress_port), true, "egress port"},
            {"instance",    &instance,    sizeof(instance),    true, "egress port instance"},
            { 0 },
    };

    if (parse_keyword_value_pairs(&argc, &argv, &kv[0]) != NO_ERROR)
        goto err;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto err;
    }

    ret = clone_session_del_member(&ctx, session_id, egress_port, instance);

err:
    psabpf_context_free(&ctx);

    return ret;
}

int do_clone_session_get(int argc, char **argv)
{
    psabpf_context_t ctx;
    psabpf_clone_session_ctx_t session;
    psabpf_clone_session_entry_t *entry;

    psabpf_context_init(&ctx);
    psabpf_context_set_pipeline(&ctx, 1);
    psabpf_clone_session_context_init(&session);
    psabpf_clone_session_id(&session, 8);

    while ((entry = psabpf_clone_session_get_next_entry(&ctx, &session)) != NULL) {
        printf("%u: port %u instance %u\n", session.id, entry->egress_port, entry->instance);
        psabpf_clone_session_entry_free(entry);
    }

    psabpf_clone_session_context_free(&session);
    psabpf_context_free(&ctx);

    return NO_ERROR;
}

int do_clone_session_help(int argc, char **argv)
{
    (void) argc; (void) argv;
    fprintf(stderr,
    "Usage: %1$s clone-session create pipe ID SESSION\n"
    "       %1$s clone-session delete pipe ID SESSION\n"
    "       %1$s clone-session add-member pipe ID SESSION egress-port OUTPUT_PORT instance INSTANCE_ID [cos CLASS_OF_SERVICE] [truncate plen_bytes BYTES]\n"
    "       %1$s clone-session del-member pipe ID SESSION egress-port OUTPUT_PORT instance INSTANCE_ID\n"
    "       %1$s clone-session get pipe ID [SESSION]\n"
    "\n"
    "       SESSION := id SESSION_ID\n"
    "",
    program_name);

    return 0;
}
