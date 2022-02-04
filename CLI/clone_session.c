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
#include <stdbool.h>
#include <bpf/bpf.h>

#include "clone_session.h"
#include <psabpf_pre.h>

int clone_session_create(__u32 pipeline_id, __u32 clone_session_id)
{
    int error = 0;
    psabpf_context_t ctx;
    psabpf_clone_session_ctx_t session;

    psabpf_context_init(&ctx);
    psabpf_context_set_pipeline(&ctx, pipeline_id);

    psabpf_clone_session_context_init(&session);
    psabpf_clone_session_id(&session, clone_session_id);

    if (psabpf_clone_session_exists(&ctx, &session)) {
        error = EEXIST;
        goto err;
    }

    if (psabpf_clone_session_create(&ctx, &session)) {
        error = -1;
        goto err;
    }

err:
    psabpf_context_free(&ctx);
    psabpf_clone_session_context_free(&session);

    return error;
}

int clone_session_delete(__u32 pipeline_id, __u32 clone_session_id)
{
    int error = 0;
    psabpf_context_t ctx;
    psabpf_clone_session_ctx_t session;

    psabpf_context_init(&ctx);
    psabpf_context_set_pipeline(&ctx, pipeline_id);

    psabpf_clone_session_context_init(&session);
    psabpf_clone_session_id(&session, clone_session_id);

    if (psabpf_clone_session_exists(&ctx, &session)) {
        error = EEXIST;
        goto err;
    }

    if (psabpf_clone_session_delete(&ctx, &session)) {
        error = -1;
        goto err;
    }

err:
    psabpf_context_free(&ctx);
    psabpf_clone_session_context_free(&session);

    return error;
}

int clone_session_add_member(psabpf_pipeline_id_t pipeline_id,
                             psabpf_clone_session_id_t clone_session_id,
                             uint32_t  egress_port,
                             uint16_t  instance,
                             uint8_t   class_of_service,
                             bool      truncate,
                             uint16_t  packet_length_bytes)
{
    int error = 0;
    psabpf_context_t ctx;
    psabpf_clone_session_ctx_t session;
    psabpf_clone_session_entry_t entry;

    psabpf_context_init(&ctx);
    psabpf_context_set_pipeline(&ctx, pipeline_id);

    psabpf_clone_session_context_init(&session);
    psabpf_clone_session_id(&session, clone_session_id);

    if (psabpf_clone_session_exists(&ctx, &session)) {
        error = EEXIST;
        goto err;
    }

    psabpf_clone_session_entry_init(&entry);
    psabpf_clone_session_entry_port(&entry, egress_port);
    psabpf_clone_session_entry_instance(&entry, instance);
    psabpf_clone_session_entry_cos(&entry, class_of_service);

    if (truncate) {
        psabpf_clone_session_entry_truncate_enable(&entry, packet_length_bytes);
    }

    error = psabpf_clone_session_entry_update(&ctx, &session, &entry);
    if (error) {
        goto err;
    }

err:
    psabpf_context_free(&ctx);
    psabpf_clone_session_context_free(&session);
    psabpf_clone_session_entry_free(&entry);

    return error;
}

// TODO: remove
static int parse_pipe_and_id(int *argc, char ***argv, __u32 *pipe, __u32 *id)
{
    if (!is_keyword(**argv, "pipe")) {
        fprintf(stderr, "expected 'pipe', got: %s\n", **argv);
        return -1;
    }
    NEXT_ARGP();
    char *endptr;
    *pipe = strtoul(**argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", **argv);
        return -1;
    }
    NEXT_ARGP();

    if (!is_keyword(**argv, "id")) {
        fprintf(stderr, "expected 'id', got: %s\n", **argv);
        return -1;
    }
    NEXT_ARGP();
    *id = strtoul(**argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", **argv);
        return -1;
    }

    return 0;
}

int do_create(int argc, char **argv)
{
    __u32 pipeline_id, clone_session_id;
    if (parse_pipe_and_id(&argc, &argv, &pipeline_id, &clone_session_id)) {
        return EINVAL;
    }

    return clone_session_create(pipeline_id, clone_session_id);
}

int do_delete(int argc, char **argv)
{
    __u32 pipeline_id, clone_session_id;
    if (parse_pipe_and_id(&argc, &argv, &pipeline_id, &clone_session_id)) {
        return EINVAL;
    }

    return clone_session_delete(pipeline_id, clone_session_id);
}

int do_add_member(int argc, char **argv)
{
    __u32 pipeline_id, clone_session_id;
    if (parse_pipe_and_id(&argc, &argv, &pipeline_id, &clone_session_id)) {
        return EINVAL;
    }

    NEXT_ARG();
    char *endptr;
    if (!is_keyword(*argv, "egress-port")) {
        fprintf(stderr, "expected 'egress-port', got: %s\n", *argv);
        return -1;
    }
    NEXT_ARG();
    __u32 egress_port = strtoul(*argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", *argv);
        return -1;
    }

    NEXT_ARG();
    if (!is_keyword(*argv, "instance")) {
        fprintf(stderr, "expected 'instance', got: %s\n", *argv);
        return -1;
    }
    NEXT_ARG();
    __u32 instance = strtoul(*argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", *argv);
        return -1;
    }

    NEXT_ARG();
    if (!is_keyword(*argv, "cos")) {
        fprintf(stderr, "expected 'cos', got: %s\n", *argv);
        return -1;
    }
    NEXT_ARG();
    __u32 cos = strtoul(*argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", *argv);
        return -1;
    }

    bool truncate = false;
    __u16 plen_bytes = 0;

    NEXT_ARG();
    if (is_keyword(*argv, "truncate")) {
        NEXT_ARG();
        if (!is_keyword(*argv, "plen_bytes")) {
            fprintf(stderr, "truncate requested, but no 'plen_bytes' provided\n");
            return -1;
        }
        NEXT_ARG();
        plen_bytes = strtoul(*argv, &endptr, 0);
        if (*endptr) {
            fprintf(stderr, "can't parse '%s'\n", *argv);
            return -1;
        }
    }

    return clone_session_add_member(pipeline_id, clone_session_id, egress_port, instance, cos, truncate, plen_bytes);
}

int do_del_member(int argc, char **argv)
{
    if (!is_keyword(*argv, "id")) {
        fprintf(stderr, "expected 'id', got: %s\n", *argv);
        return -1;
    }

    NEXT_ARG();

    char *endptr;
    __u32 id = strtoul(*argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", *argv);
        return -1;
    }

    NEXT_ARG();
    if (!is_keyword(*argv, "egress-port")) {
        fprintf(stderr, "expected 'egress-port', got: %s\n", *argv);
        return -1;
    }
    NEXT_ARG();
    __u32 egress_port = strtoul(*argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", *argv);
        return -1;
    }

    NEXT_ARG();
    if (!is_keyword(*argv, "instance")) {
        fprintf(stderr, "expected 'instance', got: %s\n", *argv);
        return -1;
    }
    NEXT_ARG();
    __u32 instance = strtoul(*argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", *argv);
        return -1;
    }

    return 0; //clone_session_del_member(, egress_port, instance);
}

int do_clone_session_help(int argc, char **argv)
{
    (void) argc; (void) argv;
    fprintf(stderr,
    "Usage: %1$s clone-session create pipe ID SESSION\n"
    "       %1$s clone-session delete pipe ID SESSION\n"
    "       %1$s clone-session add-member pipe ID SESSION egress-port OUTPUT_PORT instance INSTANCE_ID\n"
    "       %1$s clone-session del-member pipe ID SESSION egress-port OUTPUT_PORT instance INSTANCE_ID\n"
    "\n"
    "       SESSION := id SESSION_ID\n"
    "",
    program_name);

    return 0;
}
