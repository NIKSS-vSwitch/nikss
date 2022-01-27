#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../include/psabpf.h"
#include "../include/psabpf_pipeline.h"
#include "common.h"


int do_pipeline_load(int argc, char **argv)
{
    if (!is_keyword(*argv, "id")) {
        fprintf(stderr, "expected 'id', got: %s\n", *argv != NULL ? *argv : "");
        return EINVAL;
    }
    NEXT_ARG_RET();
    char *endptr;
    uint32_t id = strtoul(*argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", *argv);
        return EINVAL;
    }
    NEXT_ARG();

    if (argc < 1) {
        fprintf(stderr, "expected path to the ELF file\n");
        return EINVAL;
    } else if (argc > 1) {
        fprintf(stderr, "too many arguments\n");
        return EINVAL;
    }

    char *file = *argv;

    psabpf_context_t pipeline;
    psabpf_context_init(&pipeline);
    psabpf_context_set_pipeline(&pipeline, id);

    if (psabpf_pipeline_exists(&pipeline)) {
        fprintf(stderr, "pipeline id %u already exists\n", id);
        psabpf_context_free(&pipeline);
        return EEXIST;
    }

    int ret = psabpf_pipeline_load(&pipeline, file);
    if (ret) {
        fprintf(stdout, "An error occurred during pipeline load id %u\n", id);
        psabpf_context_free(&pipeline);
        return ret;
    }

    fprintf(stdout, "Pipeline id %u successfully loaded!\n", id);
    psabpf_context_free(&pipeline);
    return NO_ERROR;
}

int do_pipeline_unload(int argc, char **argv)
{
    int error = NO_ERROR;
    if (!is_keyword(*argv, "id")) {
        fprintf(stderr, "expected 'id', got: %s\n", *argv != NULL ? *argv : "");
        return EINVAL;
    }
    NEXT_ARG_RET();
    char *endptr;
    uint32_t id = strtoul(*argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", *argv);
        return EINVAL;
    }

    if (argc > 1) {
        fprintf(stderr, "too many arguments\n");
        return EINVAL;
    }

    psabpf_context_t pipeline;
    psabpf_context_init(&pipeline);
    psabpf_context_set_pipeline(&pipeline, id);

    if (!psabpf_pipeline_exists(&pipeline)) {
        fprintf(stderr, "pipeline with given id %u does not exist\n", id);
        error = ENOENT;
        goto err;
    }

    error = psabpf_pipeline_unload(&pipeline);
    if (error) {
        fprintf(stdout, "An error occurred during pipeline unload id %u\n", id);
        goto err;
    }

    fprintf(stdout, "Pipeline id %u successfully unloaded!\n", id);
err:
    psabpf_context_free(&pipeline);
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
    psabpf_context_t pipeline;
    psabpf_context_init(&pipeline);

    if ((ret = parse_pipeline_id(&argc, &argv, &pipeline)) != NO_ERROR)
        goto err;

    if ((ret = parse_interface(&argc, &argv, &intf)) != NO_ERROR)
        goto err;

    if (argc != 0) {
        fprintf(stderr, "too many arguments\n");
        ret = EINVAL;
        goto err;
    }

    ret = psabpf_pipeline_add_port(&pipeline, intf);
    if (ret) {
        fprintf(stderr, "failed to add port: %s\n", strerror(ret));
    }

err:
    psabpf_context_free(&pipeline);
    return ret;
}

int do_pipeline_port_del(int argc, char **argv)
{
    int ret;
    const char *intf;
    psabpf_context_t pipeline;
    psabpf_context_init(&pipeline);

    if ((ret = parse_pipeline_id(&argc, &argv, &pipeline)) != NO_ERROR)
        goto err;

    if ((ret = parse_interface(&argc, &argv, &intf)) != NO_ERROR)
        goto err;

    if (argc != 0) {
        fprintf(stderr, "too many arguments\n");
        ret = EINVAL;
        goto err;
    }

    ret = psabpf_pipeline_del_port(&pipeline, intf);
    if (ret) {
        fprintf(stderr, "failed to delete port: %s\n", strerror(ret));
    }

err:
    psabpf_context_free(&pipeline);
    return ret;
}

int do_pipeline_help(int argc, char **argv)
{
    (void) argc; (void) argv;
    fprintf(stderr,
            "Usage: %1$s pipeline load id ID PATH\n"
            "       %1$s pipeline unload id ID\n"
            "       %1$s add-port pipe id ID dev DEV\n"
            "       %1$s del-port pipe id ID dev DEV\n"
            "",
            program_name);
    return NO_ERROR;
}
