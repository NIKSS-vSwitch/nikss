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
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <jansson.h>

#include <psabpf.h>
#include <psabpf_pipeline.h>
#include "common.h"

static json_t * json_port_entry(const char *intf, int ifindex)
{
    json_t *root = json_object();
    json_object_set_new(root, "name", json_string(intf));
    json_object_set_new(root, "port_id", json_integer((json_int_t) ifindex));

    return root;
}

static void print_port(const char *intf, int ifindex) {
    json_t *root = json_port_entry(intf, ifindex);
    json_dumpf(root, stdout, JSON_INDENT(4) | JSON_ENSURE_ASCII);
    json_decref(root);
}

static int print_pipeline_json(psabpf_context_t *ctx)
{
    psabpf_port_list_t list;
    psabpf_port_list_init(&list, ctx);

    json_t *root = json_object();
    json_t *pipeline = json_object();
    json_t *ports_root = json_array();

    json_object_set_new(root, "pipeline", pipeline);
    json_object_set_new(pipeline, "id", json_integer(psabpf_context_get_pipeline(ctx)));
    json_object_set_new(pipeline, "ports", ports_root);

    psabpf_port_spec_t *port;
    while ((port = psabpf_port_list_get_next_port(&list)) != NULL) {
        json_t *entry = json_port_entry(psabpf_port_spec_get_name(port), (int) psabpf_port_sepc_get_id(port));
        json_array_append(ports_root, entry);
        psabpf_port_spec_free(port);
    }

    psabpf_port_list_free(&list);

    json_dumpf(root, stdout, JSON_INDENT(4) | JSON_ENSURE_ASCII);
    json_decref(root);

    return NO_ERROR;
}

static int parse_pipeline_id_without_pipe_keyword(int *argc, char ***argv, uint32_t *id)
{
    if (!is_keyword(**argv, "id")) {
        fprintf(stderr, "expected 'id', got: %s\n", **argv != NULL ? **argv : "");
        return EINVAL;
    }
    NEXT_ARGP_RET();
    char *endptr;
    *id = strtoul(**argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", **argv);
        return EINVAL;
    }
    NEXT_ARGP();
    return NO_ERROR;
}

int do_pipeline_load(int argc, char **argv)
{
    uint32_t id = 0;

    if (parse_pipeline_id_without_pipe_keyword(&argc, &argv, &id) != NO_ERROR)
        return EINVAL;

    if (argc < 1) {
        fprintf(stderr, "expected path to the ELF file\n");
        return EINVAL;
    } else if (argc > 1) {
        fprintf(stderr, "too many arguments\n");
        return EINVAL;
    }

    char *file = *argv;

    psabpf_context_t ctx;
    psabpf_context_init(&ctx);
    psabpf_context_set_pipeline(&ctx, id);

    if (psabpf_pipeline_exists(&ctx)) {
        fprintf(stderr, "pipeline id %u already exists\n", id);
        psabpf_context_free(&ctx);
        return EEXIST;
    }

    int ret = psabpf_pipeline_load(&ctx, file);
    if (ret) {
        fprintf(stdout, "An error occurred during pipeline load id %u\n", id);
        psabpf_context_free(&ctx);
        return ret;
    }

    fprintf(stdout, "Pipeline id %u successfully loaded!\n", id);
    psabpf_context_free(&ctx);
    return NO_ERROR;
}

int do_pipeline_unload(int argc, char **argv)
{
    int error = NO_ERROR;
    uint32_t id = 0;

    if (parse_pipeline_id_without_pipe_keyword(&argc, &argv, &id) != NO_ERROR)
        return EINVAL;

    if (argc > 0) {
        fprintf(stderr, "too many arguments\n");
        return EINVAL;
    }

    psabpf_context_t ctx;
    psabpf_context_init(&ctx);
    psabpf_context_set_pipeline(&ctx, id);

    if (!psabpf_pipeline_exists(&ctx)) {
        fprintf(stderr, "pipeline with given id %u does not exist\n", id);
        error = ENOENT;
        goto err;
    }

    error = psabpf_pipeline_unload(&ctx);
    if (error) {
        fprintf(stdout, "An error occurred during pipeline unload id %u\n", id);
        goto err;
    }

    fprintf(stdout, "Pipeline id %u successfully unloaded!\n", id);
err:
    psabpf_context_free(&ctx);
    return error;
}

static int parse_interface(int *argc, char ***argv, const char **interface)
{
    if (!is_keyword(**argv, "dev")) {
        fprintf(stderr, "expected 'dev', got: %s\n", **argv != NULL ? **argv : "");
        return EINVAL;
    }

    NEXT_ARGP_RET();

    *interface = **argv;

    NEXT_ARGP();

    return NO_ERROR;
}

int do_pipeline_port_add(int argc, char **argv)
{
    int ret;
    const char *intf;
    psabpf_context_t ctx;
    psabpf_context_init(&ctx);

    if ((ret = parse_pipeline_id(&argc, &argv, &ctx)) != NO_ERROR)
        goto err;

    if ((ret = parse_interface(&argc, &argv, &intf)) != NO_ERROR)
        goto err;

    if (argc != 0) {
        fprintf(stderr, "too many arguments\n");
        ret = EINVAL;
        goto err;
    }

    int ifindex = 0;
    ret = psabpf_pipeline_add_port(&ctx, intf, &ifindex);
    if (ret) {
        fprintf(stderr, "failed to add port: %s\n", strerror(ret));
    } else {
        print_port(intf, ifindex);
    }

err:
    psabpf_context_free(&ctx);
    return ret;
}

int do_pipeline_port_del(int argc, char **argv)
{
    int ret;
    const char *intf;
    psabpf_context_t ctx;
    psabpf_context_init(&ctx);

    if ((ret = parse_pipeline_id(&argc, &argv, &ctx)) != NO_ERROR)
        goto err;

    if ((ret = parse_interface(&argc, &argv, &intf)) != NO_ERROR)
        goto err;

    if (argc != 0) {
        fprintf(stderr, "too many arguments\n");
        ret = EINVAL;
        goto err;
    }

    ret = psabpf_pipeline_del_port(&ctx, intf);
    if (ret) {
        fprintf(stderr, "failed to delete port: %s\n", strerror(ret));
    }

err:
    psabpf_context_free(&ctx);
    return ret;
}

int do_pipeline_show(int argc, char **argv)
{
    psabpf_context_t ctx;
    int ret_code = EINVAL;
    uint32_t id = 0;

    if (parse_pipeline_id_without_pipe_keyword(&argc, &argv, &id) != NO_ERROR)
        return EINVAL;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        return EINVAL;
    }

    psabpf_context_init(&ctx);
    psabpf_context_set_pipeline(&ctx, id);

    ret_code = print_pipeline_json(&ctx);

    psabpf_context_free(&ctx);
    return ret_code;
}

int do_pipeline_help(int argc, char **argv)
{
    (void) argc; (void) argv;
    fprintf(stderr,
            "Usage: %1$s pipeline load id ID PATH\n"
            "       %1$s pipeline unload id ID\n"
            "       %1$s pipeline show id ID\n"
            "       %1$s add-port pipe id ID dev DEV\n"
            "       %1$s del-port pipe id ID dev DEV\n"
            "",
            program_name);
    return NO_ERROR;
}
