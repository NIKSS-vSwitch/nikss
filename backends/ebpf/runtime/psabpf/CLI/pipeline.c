#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "../include/psabpf.h"
#include "../include/psabpf_pipeline.h"
#include "common.h"


int do_load(int argc, char **argv)
{
    if (!is_keyword(*argv, "id")) {
        fprintf(stderr, "expected 'id', got: %s\n", *argv);
        return EINVAL;
    }
    NEXT_ARG();
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
    }

    char *file = *argv;

    psabpf_pipeline_t pipeline;
    psabpf_pipeline_init(&pipeline);
    psabpf_pipeline_setid(&pipeline, id);

    if (psabpf_pipeline_exists(&pipeline)) {
        fprintf(stderr, "pipeline id %d already exists\n", id);
        psabpf_pipeline_free(&pipeline);
        return EEXIST;
    }

    psabpf_pipeline_setobj(&pipeline, file);

    if (psabpf_pipeline_load(&pipeline)) {
        psabpf_pipeline_free(&pipeline);
        return -1;
    }

    fprintf(stdout, "Pipeline id %d successfully loaded!\n", id);
    psabpf_pipeline_free(&pipeline);
    return 0;
}

int do_unload(int argc, char **argv)
{
    int error = NO_ERROR;
    if (!is_keyword(*argv, "id")) {
        fprintf(stderr, "expected 'id', got: %s\n", *argv);
        return -1;
    }
    NEXT_ARG();
    char *endptr;
    uint32_t id = strtoul(*argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", *argv);
        return -1;
    }

    psabpf_pipeline_t pipeline;
    psabpf_pipeline_init(&pipeline);
    psabpf_pipeline_setid(&pipeline, id);

    if (!psabpf_pipeline_exists(&pipeline)) {
        fprintf(stderr, "pipeline with given id %d does not exist\n", id);
        error = EINVAL;
        goto err;
    }

    if (psabpf_pipeline_unload(&pipeline)) {
        error = -1;
        goto err;
    }

    fprintf(stdout, "Pipeline id %d successfully unloaded!\n", id);
err:
    psabpf_pipeline_free(&pipeline);
    return error;
}

int do_port_add(int argc, char **argv)
{
    if (!is_keyword(*argv, "id")) {
        fprintf(stderr, "expected 'id', got: %s\n", *argv);
        return -1;
    }
    NEXT_ARG();
    char *endptr;
    uint32_t id = strtoul(*argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", *argv);
        return -1;
    }
    NEXT_ARG();

    if (argc < 1) {
        fprintf(stderr, "expected interface name\n");
        return EINVAL;
    }
    char *intf = *argv;

    psabpf_pipeline_t pipeline;
    psabpf_pipeline_init(&pipeline);
    psabpf_pipeline_setid(&pipeline, id);

    if (!psabpf_pipeline_exists(&pipeline)) {
        psabpf_pipeline_free(&pipeline);
        return EEXIST;
    }

    int ret = psabpf_pipeline_add_port(&pipeline, intf);
    if (ret) {
        fprintf(stderr, "failed to add port: %s\n", strerror(ret));
        psabpf_pipeline_free(&pipeline);
        return ret;
    }

    psabpf_pipeline_free(&pipeline);
    return 0;
}

int do_port_del(int argc, char **argv)
{
    if (!is_keyword(*argv, "id")) {
        fprintf(stderr, "expected 'id', got: %s\n", *argv);
        return -1;
    }
    NEXT_ARG();
    char *endptr;
    uint32_t id = strtoul(*argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", *argv);
        return -1;
    }
    NEXT_ARG();

    if (argc < 1) {
        fprintf(stderr, "expected interface name\n");
        return EINVAL;
    }
    char *intf = *argv;

    psabpf_pipeline_t pipeline;
    psabpf_pipeline_init(&pipeline);
    psabpf_pipeline_setid(&pipeline, id);

    if (!psabpf_pipeline_exists(&pipeline)) {
        psabpf_pipeline_free(&pipeline);
        return EEXIST;
    }

    int ret = psabpf_pipeline_del_port(&pipeline, intf);
    if (ret) {
        fprintf(stderr, "failed to delete port: %s\n", strerror(ret));
        psabpf_pipeline_free(&pipeline);
        return ret;
    }

    psabpf_pipeline_free(&pipeline);
    return 0;
}

int do_pipeline_help(int argc, char **argv)
{
    (void) argc; (void) argv;
    fprintf(stderr,
            "Usage: %1$s pipeline load id ID PATH\n"
            "       %1$s pipeline unload id ID\n"
            "",
            program_name);
    return 0;
}
