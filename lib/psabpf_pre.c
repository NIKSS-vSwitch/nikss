#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include "bpf/bpf.h"
#include "bpf/libbpf.h"

#include <psabpf_pre.h>
#include "../include/bpf_defs.h"
#include "common.h"
#include "btf.h"

struct list_key_t {
    __u32 port;
    __u16 instance;
};
typedef struct list_key_t elem_t;

struct element {
    psabpf_clone_session_entry_t entry;
    elem_t next_id;
} __attribute__((aligned(4)));

/******************************************************************************
 * Common functions
 ******************************************************************************/

static int open_pr_maps(psabpf_context_t *ctx, const char *pr_map_outer, const char *pr_map_inner,
                        psabpf_bpf_map_descriptor_t *outer, psabpf_bpf_map_descriptor_t *inner)
{
    outer->fd = -1;
    if (inner != NULL)
        inner->fd = -1;

    int ret = open_bpf_map(ctx, pr_map_outer, NULL, outer);
    if (ret != NO_ERROR) {
        fprintf(stderr, "failed to open %s: %s\n", pr_map_outer, strerror(ret));
        goto err;
    }

    if (pr_map_inner != NULL) {
        ret = open_bpf_map(ctx, pr_map_inner, NULL, inner);
        if (ret != NO_ERROR) {
            fprintf(stderr, "failed to open %s: %s\n", pr_map_inner, strerror(ret));
            goto err;
        }
    }

err:
    if (ret != NO_ERROR) {
        if (inner != NULL)
            close_object_fd(&inner->fd);
        close_object_fd(&outer->fd);
    }
    return ret;
}

static int open_session_map(psabpf_bpf_map_descriptor_t *pr_map,
                            psabpf_bpf_map_descriptor_t *session_map, uint32_t session)
{
    session_map->fd = -1;

    if (pr_map->fd < 0) {
        fprintf(stderr, "map not opened\n");
        return EBADF;
    }
    if (pr_map->key_size != sizeof(uint32_t) || pr_map->value_size != sizeof(uint32_t)) {
        fprintf(stderr, "invalid session/group map\n");
        return EINVAL;
    }

    uint32_t inner_map_id;
    int ret = bpf_map_lookup_elem(pr_map->fd, &session, &inner_map_id);
    if (ret != 0) {
        ret = errno;
        fprintf(stderr, "could not find session/group: %s\n", strerror(ret));
        return ret;
    }

    session_map->fd = bpf_map_get_fd_by_id(inner_map_id);
    if (session_map->fd < 0) {
        ret = errno;
        fprintf(stderr, "could not get inner map: %s\n", strerror(ret));
        return ret;
    }

    return update_map_info(session_map);
}

static int do_create_pre_session(psabpf_bpf_map_descriptor_t *pr_map,
                                 psabpf_bpf_map_descriptor_t *session_template, uint32_t session)
{
    int error_code;
    if (pr_map->fd < 0 || session_template->fd < 0) {
        fprintf(stderr, "maps not opened\n");
        return EBADF;
    }
    if (pr_map->key_size != sizeof(session)) {
        fprintf(stderr, "key map size must be equal to %lu\n", sizeof(session));
        return EINVAL;
    }
    if (session_template->key_size != sizeof(elem_t) || session_template->value_size != sizeof(struct element)) {
        fprintf(stderr, "invalid session/group map template\n");
        return EINVAL;
    }

    /* create inner map */
    struct bpf_create_map_attr attr = {
            .key_size = session_template->key_size,
            .value_size = session_template->value_size,
            .max_entries = session_template->max_entries,
            .map_type = session_template->type,
    };
    int inner_map_fd = bpf_create_map_xattr(&attr);
    if (inner_map_fd < 0) {
        error_code = errno;
        fprintf(stderr, "failed to create inner session/group map: %s\n", strerror(error_code));
        return error_code;
    }

    /* add head in inner map */
    elem_t head_idx = { 0 };
    struct element head_elem =  { 0 };
    error_code = bpf_map_update_elem(inner_map_fd, &head_idx, &head_elem, 0);
    if (error_code != 0) {
        error_code = errno;
        printf("failed to add head to the list: %s\n", strerror(error_code));
        goto ret;
    }

    /* add inner map to outer map */
    error_code = bpf_map_update_elem(pr_map->fd, &session, &inner_map_fd, BPF_NOEXIST);
    if (error_code != 0) {
        error_code = errno;
        fprintf(stderr, "failed to add session/group to map %s\n", strerror(error_code));
        goto ret;
    }

ret:
    close_object_fd(&inner_map_fd);
    return error_code;
}

static int create_pre_session(psabpf_context_t *ctx, const char *pr_map, const char *pr_map_inner, uint32_t session)
{
    if (ctx == NULL || session == 0) {
        fprintf(stderr, "invalid session/group or context\n");
        return EINVAL;
    }

    psabpf_bpf_map_descriptor_t outer_map, inner_map;

    int ret = open_pr_maps(ctx, pr_map, pr_map_inner, &outer_map, &inner_map);
    if (ret != NO_ERROR)
        goto err;

    ret = do_create_pre_session(&outer_map, &inner_map, session);
    if (ret != NO_ERROR)
        fprintf(stderr, "failed to create session/group: %s\n", strerror(ret));

err:
    close_object_fd(&inner_map.fd);
    close_object_fd(&outer_map.fd);
    return ret;
}

static int insert_pre_session_entry(psabpf_bpf_map_descriptor_t *pr_map, uint32_t session)
{
    psabpf_bpf_map_descriptor_t session_map;
    int ret;

    return NO_ERROR;
}

/******************************************************************************
 * Clone session
 ******************************************************************************/

void psabpf_clone_session_context_init(psabpf_clone_session_ctx_t *ctx)
{
    if (ctx == NULL)
        return;
    memset( ctx, 0, sizeof(psabpf_clone_session_ctx_t));
}

void psabpf_clone_session_context_free(psabpf_clone_session_ctx_t *ctx)
{
    if (ctx == NULL)
        return;
    memset( ctx, 0, sizeof(psabpf_clone_session_ctx_t));
}

void psabpf_clone_session_id(psabpf_clone_session_ctx_t *ctx, psabpf_clone_session_id_t id)
{
    if (ctx == NULL)
        return;
    ctx->id = id;
}

// TODO: implement
int psabpf_clone_session_exists(psabpf_context_t *ctx, psabpf_clone_session_ctx_t *session)
{
    (void) ctx; (void) session;
    return 0;
}

int psabpf_clone_session_create(psabpf_context_t *ctx, psabpf_clone_session_ctx_t *session)
{
    return create_pre_session(ctx, CLONE_SESSION_TABLE, CLONE_SESSION_TABLE_INNER, session->id);
}

void psabpf_clone_session_entry_init(psabpf_clone_session_entry_t *entry)
{
    if (entry == NULL)
        return;
    memset( entry, 0, sizeof(psabpf_clone_session_entry_t));
}

void psabpf_clone_session_entry_free(psabpf_clone_session_entry_t *entry)
{
    if (entry == NULL)
        return;
    memset(entry, 0, sizeof(psabpf_clone_session_entry_t));
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

void psabpf_clone_session_entry_truncate_enable(psabpf_clone_session_entry_t *entry, uint16_t packet_length_bytes)
{
    entry->truncate = true;
    entry->packet_length_bytes = packet_length_bytes;
}

void psabpf_clone_session_entry_truncate_disable(psabpf_clone_session_entry_t *entry)
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

/******************************************************************************
 * Multicast groups
 ******************************************************************************/

void psabpf_mcast_grp_context_init(psabpf_mcast_grp_ctx_t *group)
{
    if (group == NULL)
        return;
    memset(group, 0, sizeof(psabpf_mcast_grp_ctx_t));
}

void psabpf_mcast_grp_context_free(psabpf_mcast_grp_ctx_t *group)
{
    if (group == NULL)
        return;
    memset(group, 0, sizeof(psabpf_mcast_grp_ctx_t));
}

void psabpf_mcast_grp_id(psabpf_mcast_grp_ctx_t *group, psabpf_mcast_grp_id_t mcast_grp_id)
{
    if (group != NULL)
        group->id = mcast_grp_id;
}

int psabpf_mcast_grp_create(psabpf_context_t *ctx, psabpf_mcast_grp_ctx_t *group)
{
    return create_pre_session(ctx, MULTICAST_GROUP_TABLE, MULTICAST_GROUP_TABLE_INNER, group->id);
}

int psabpf_mcast_grp_exists(psabpf_context_t *ctx, psabpf_mcast_grp_ctx_t *group)
{
    return NO_ERROR;
}

int psabpf_mcast_grp_delete(psabpf_context_t *ctx, psabpf_mcast_grp_ctx_t *group)
{
    return NO_ERROR;
}

void psabpf_mcast_grp_member_init(psabpf_mcast_grp_member_t *member)
{
    if (member == NULL)
        return;
    memset(member, 0, sizeof(psabpf_mcast_grp_member_t));
}

void psabpf_mcast_grp_member_free(psabpf_mcast_grp_member_t *member)
{
    if (member == NULL)
        return;
    memset(member, 0, sizeof(psabpf_mcast_grp_member_t));
}

void psabpf_mcast_grp_member_port(psabpf_mcast_grp_member_t *member, uint32_t egress_port)
{
    if (member != NULL)
        member->egress_port = egress_port;
}

void psabpf_mcast_grp_member_instance(psabpf_mcast_grp_member_t *member, uint16_t instance)
{
    if (member != NULL)
        member->instance = instance;
}

int psabpf_mcast_grp_member_update(psabpf_context_t *ctx, psabpf_mcast_grp_ctx_t *group, psabpf_mcast_grp_member_t *member)
{
    return NO_ERROR;
}

int psabpf_mcast_grp_member_exists(psabpf_context_t *ctx, psabpf_mcast_grp_ctx_t *group, psabpf_mcast_grp_member_t *member)
{
    return NO_ERROR;
}

int psabpf_mcast_grp_member_delete(psabpf_context_t *ctx, psabpf_mcast_grp_ctx_t *group, psabpf_mcast_grp_member_t *member)
{
    return NO_ERROR;
}
