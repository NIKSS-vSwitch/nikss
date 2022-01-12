#include "bpf/bpf.h"
#include <errno.h>
#include <getopt.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#include "clone_session.h"
#include "../include/psabpf.h"
#include "../include/psabpf_clone_session.h"
#include "../include/bpf_defs.h"

struct list_key_t {
    __u32 port;
    __u16 instance;
};
typedef struct list_key_t elem_t;

struct element {
    struct psabpf_clone_session_entry entry;
    elem_t next_id;
} __attribute__((aligned(4)));

double get_current_time() {
    struct timeval t;
    gettimeofday(&t, 0);
    return t.tv_sec + t.tv_usec*1e-6;
}
static double start_time;
static double end_time;

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

// TODO: use psabpf library
int clone_session_del_member(__u32 clone_session_id, __u32 egress_port, __u16 instance)
{
    if (egress_port == 0 || instance == 0) {
        fprintf(stderr, "Invalid value of 'egress-port' or 'instance' provided");
        return -1;
    }

    start_time = get_current_time();
    int error = 0;

    char pinned_file[256];
    snprintf(pinned_file, sizeof(pinned_file), "%s/%s", BPF_FS,
             CLONE_SESSION_TABLE);

    long outer_map_fd = bpf_obj_get(pinned_file);
    if (outer_map_fd < 0) {
        fprintf(stderr, "could not find map %s. Clone session doesn't exists? [%s].\n",
                CLONE_SESSION_TABLE, strerror(errno));
        return -1;
    }

    uint32_t inner_map_id;
    int ret = bpf_map_lookup_elem(outer_map_fd, &clone_session_id, &inner_map_id);
    if (ret < 0) {
        fprintf(stderr, "could not find inner map [%s]\n", strerror(errno));
        return -1;
    }

    int inner_fd = bpf_map_get_fd_by_id(inner_map_id);

    elem_t prev_elem_key = {0, 0};
    struct element elem;
    elem_t key = {0, 0};
    do {
        ret = bpf_map_lookup_elem(inner_fd, &key, &elem);
        if (ret < 0) {
            fprintf(stderr, "error getting element from list (egress_port=%d, instance=%d), does it exist?, "
                            "err = %d, errno = %d\n", elem.next_id.port, elem.next_id.instance, ret, errno);
            return -1;
        }

        if (elem.next_id.instance == instance && elem.next_id.port == egress_port) {
            prev_elem_key = key;
            break;
        }
        key = elem.next_id;
    } while (elem.next_id.port != 0 && elem.next_id.instance != 0);

    struct element elem_to_delete;
    elem_t key_to_del = {egress_port, instance};
    ret = bpf_map_lookup_elem(inner_fd, &key_to_del, &elem_to_delete);
    if (ret < 0) {
        fprintf(stderr, "error getting element to delete, err = %d, errno = %d\n", ret, errno);
        return -1;
    }

    struct element prev_elem;
    ret = bpf_map_lookup_elem(inner_fd, &prev_elem_key, &prev_elem);
    if (ret < 0) {
        fprintf(stderr, "error getting previous element, err = %d, errno = %d\n", ret, errno);
        return -1;
    }

    prev_elem.next_id = elem_to_delete.next_id;

    ret = bpf_map_update_elem(inner_fd, &prev_elem_key, &prev_elem, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "failed to update previous element, err = %d, errno = %d\n", ret, errno);
        return -1;
    }

    ret = bpf_map_delete_elem(inner_fd, &key_to_del);
    if (ret < 0) {
        fprintf(stderr, "failed to delete element, err = %d, errno = %d\n", ret, errno);
        return -1;
    }

    fprintf(stdout, "Clone session member (egress_port=%d, instance=%d) successfully deleted.\n",
            egress_port, instance);

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

    return clone_session_del_member(id, egress_port, instance);
}

int do_clone_session_help(int argc, char **argv)
{
    fprintf(stderr,
    "Usage: %1$s clone-session create SESSION\n"
    "       %1$s clone-session delete SESSION\n"
    "       %1$s clone-session add-member SESSION egress-port OUTPUT_PORT instance INSTANCE_ID\n"
    "       %1$s clone-session del-member SESSION egress-port OUTPUT_PORT instance INSTANCE_ID\n"
    "\n"
    "       SESSION := id SESSION_ID\n"
    "",
    program_name);

    return 0;
}
