#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include "bpf/bpf.h"
#include "bpf/libbpf.h"

#include "../include/psabpf_clone_session.h"
#include "../include/bpf_defs.h"

struct list_key_t {
    __u32 port;
    __u16 instance;
};
typedef struct list_key_t elem_t;

struct element {
    psabpf_clone_session_entry_t entry;
    elem_t next_id;
} __attribute__((aligned(4)));


void psabpf_clone_session_context_init(psabpf_clone_session_ctx_t *ctx)
{
    memset( ctx, 0, sizeof(psabpf_clone_session_ctx_t));
}

void psabpf_clone_session_context_free(psabpf_clone_session_ctx_t *ctx)
{
    if ( ctx == NULL )
        return;

    memset( ctx, 0, sizeof(psabpf_clone_session_ctx_t));
}

void psabpf_clone_session_id(psabpf_clone_session_ctx_t *ctx, psabpf_clone_session_id_t id)
{
    ctx->id = id;
}

// TODO: implement
int psabpf_clone_session_exists(psabpf_context_t *ctx, psabpf_clone_session_ctx_t *session)
{
    return 0;
}

int psabpf_clone_session_create(psabpf_context_t *ctx, psabpf_clone_session_ctx_t *session)
{
    int error;

    if (session->id == 0) {
        // it means that ID was not initialized
        return EINVAL;
    }

    psabpf_pipeline_id_t pipeline_id = ctx->pipeline_id;
    psabpf_clone_session_id_t clone_session_id = session->id;

    struct bpf_create_map_attr attr = { NULL, };
    attr.map_type = BPF_MAP_TYPE_HASH;
    char name[256];
    snprintf(name, sizeof(name), "clone_session_%d", clone_session_id);

    attr.name = name;
    attr.key_size = sizeof(elem_t);
    attr.value_size = sizeof(struct element);
    attr.max_entries = PSABPF_MAX_CLONE_SESSION_MEMBERS;
    attr.map_flags = 0;

    int inner_map_fd = bpf_create_map_xattr(&attr);
    if (inner_map_fd < 0) {
        // FIXME: should be a debug option
        printf("failed to create new clone session\n");
        return -1;
    }

    char path[256];
    snprintf(path, sizeof(path), "%s/pipeline%d/maps/clone_session_%d", BPF_FS, pipeline_id, clone_session_id);
    error = bpf_obj_pin(inner_map_fd, path);
    if (error < 0) {
        printf("failed to pin new clone session to a file [%s]\n", strerror(errno));
        goto ret;
    }

    elem_t head_idx = {};
    head_idx.instance = 0;
    head_idx.port = 0;
    struct element head_elem =  {
            .entry = { 0 },
            .next_id = { 0 },
    };
    error = bpf_map_update_elem(inner_map_fd, &head_idx, &head_elem, 0);
    if (error < 0) {
        printf("failed to add head to the list [%s]\n", strerror(errno));
        goto ret;
    }

    char pinned_file[256];
    snprintf(pinned_file, sizeof(pinned_file), "%s/pipeline%d/maps/%s", BPF_FS,
             pipeline_id, CLONE_SESSION_TABLE);

    long outer_map_fd = bpf_obj_get(pinned_file);
    if (outer_map_fd < 0) {
        fprintf(stderr, "could not find map %s [%s].\n",
                CLONE_SESSION_TABLE, strerror(errno));
        error = -1;
        goto ret;
    }

    error = bpf_map_update_elem((unsigned int)outer_map_fd, &clone_session_id, &inner_map_fd, 0);
    if (error < 0) {
        fprintf(stderr, "failed to create clone session with id %u [%s].\n",
                clone_session_id, strerror(errno));
        goto ret;
    }

    printf("Clone session ID %d successfully created\n", clone_session_id);

    close(inner_map_fd);
    close(outer_map_fd);

    ret:
    if (inner_map_fd > 0) {
        close(inner_map_fd);
    }

    if (outer_map_fd > 0) {
        close(outer_map_fd);
    }

    return error;
}

void psabpf_clone_session_entry_init(psabpf_clone_session_entry_t *entry)
{
    memset( entry, 0, sizeof(psabpf_clone_session_entry_t));
}

void psabpf_clone_session_entry_free(psabpf_clone_session_entry_t *entry)
{
    if ( entry == NULL )
        return;

    memset( entry, 0, sizeof(psabpf_clone_session_entry_t));
}

void psabpf_clone_session_entry_port(psabpf_clone_session_entry_t *entry, uint32_t egress_port)
{
    entry->egress_port = egress_port;
}

void psabpf_clone_session_entry_instance(psabpf_clone_session_entry_t *entry, uint16_t instance)
{
    entry->instance = instance;
}

void psabpf_clone_session_entry_cos(psabpf_clone_session_entry_t *entry, uint8_t class_of_service)
{
    entry->class_of_service = class_of_service;
}

int psabpf_clone_session_entry_truncate_enable(psabpf_clone_session_entry_t *entry, uint16_t packet_length_bytes)
{
    entry->truncate = true;
    entry->packet_length_bytes = packet_length_bytes;
}

int psabpf_clone_session_entry_truncate_disable(psabpf_clone_session_entry_t *entry)
{
    entry->truncate = false;
    entry->packet_length_bytes = 0;
}

int psabpf_clone_session_entry_update(psabpf_context_t *ctx, psabpf_clone_session_ctx_t *session, psabpf_clone_session_entry_t *entry)
{
    if ( entry == NULL || ( entry->instance == 0 && entry->egress_port == 0 ) ) {
        return EINVAL;
    }

    printf("egress port %u", entry->egress_port);

    psabpf_clone_session_id_t clone_session_id = session->id;

    char pinned_file[256];
    snprintf(pinned_file, sizeof(pinned_file), "%s/pipeline%d/maps/%s", BPF_FS,
             ctx->pipeline_id, CLONE_SESSION_TABLE);

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

    /* 1. Gead head. */
    elem_t head_idx = {0, 0};
    struct element head;
    ret = bpf_map_lookup_elem(inner_fd, &head_idx, &head);
    if (ret < 0) {
        fprintf(stderr, "error getting head of list, err = %d, errno = %d\n", ret, errno);
        return -1;
    }

    /* 2. Allocate new element and put in the data. */
    struct element el = {
            .entry = *entry,
            /* 3. Make next of new node as next of head */
            .next_id = head.next_id,
    };
    elem_t idx;
    idx.port = entry->egress_port;
    idx.instance = entry->instance;
    ret = bpf_map_update_elem(inner_fd, &idx, &el, BPF_NOEXIST);
    if (ret < 0 && errno == EEXIST) {
        fprintf(stderr, "Clone session member [port=%d, instance=%d] already exists. "
                        "Increment 'instance' to clone more than one packet to the same port.\n",
                entry->egress_port,
                entry->instance);
        return -1;
    } else if (ret < 0) {
        printf("error creating list element, err = %d, errno = %d\n", ret, errno);
        return -1;
    }

    /* 4. move the head to point to the new node */
    head.next_id = idx;
    ret = bpf_map_update_elem(inner_fd, &head_idx, &head, 0);
    if (ret < 0) {
        printf("error updating head, err = %d [%s]\n", ret, strerror(errno));
        return -1;
    }

    fprintf(stdout, "New member of clone session %d added successfully\n",
            clone_session_id);

    return 0;
}

int psabpf_clone_session_delete(psabpf_context_t *ctx, psabpf_clone_session_ctx_t *session)
{
    int error = 0;

    if ( session == NULL || session->id == 0 )
        return EINVAL;

    psabpf_clone_session_id_t clone_session_id = session->id;

    char session_map_path[256];
    snprintf(session_map_path, sizeof(session_map_path), "%s/pipeline%d/maps/clone_session_%d", BPF_FS,
             ctx->pipeline_id, clone_session_id);

    char pinned_file[256];
    snprintf(pinned_file, sizeof(pinned_file), "%s/pipeline%d/maps/%s", BPF_FS,
             ctx->pipeline_id, CLONE_SESSION_TABLE);
    long outer_map_fd = bpf_obj_get(pinned_file);
    if (outer_map_fd < 0) {
        fprintf(stderr, "could not find map %s [%s].\n",
                CLONE_SESSION_TABLE, strerror(errno));
        error = -1;
        goto ret;
    }

    error = bpf_map_delete_elem((int)outer_map_fd, &clone_session_id);
    if (error < 0) {
        fprintf(stderr, "failed to clear clone session with id %u [%s].\n",
                clone_session_id, strerror(errno));
        goto ret;
    }

    if (remove(session_map_path)) {
        fprintf(stderr, "failed to delete clone session %u [%s].\n",
                clone_session_id, strerror(errno));
        error = -1;
        goto ret;
    }

    printf("Successfully deleted clone session with ID %d\n", clone_session_id);

    ret:
    if (outer_map_fd > 0) {
        close(outer_map_fd);
    }

    return error;
}
