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

#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include <nikss/nikss_pre.h>

#include "bpf_defs.h"
#include "btf.h"
#include "common.h"

struct list_key_t {
    __u32 port;
    __u16 instance;
};
typedef struct list_key_t elem_t;

struct element {
    nikss_clone_session_entry_t entry;
    elem_t next_id;
} __attribute__((aligned(4)));

/******************************************************************************
 * Common functions
 ******************************************************************************/

static int open_pr_maps(nikss_context_t *ctx, const char *pr_map_outer, const char *pr_map_inner,
                        nikss_bpf_map_descriptor_t *outer, nikss_bpf_map_descriptor_t *inner)
{
    outer->fd = -1;
    if (inner != NULL) {
        inner->fd = -1;
    }

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
        if (inner != NULL) {
            close_object_fd(&inner->fd);
        }
        close_object_fd(&outer->fd);
    }
    return ret;
}

static int open_session_map(nikss_bpf_map_descriptor_t *pr_map,
                            nikss_bpf_map_descriptor_t *session_map, uint32_t session)
{
    session_map->fd = -1;
    session_map->key_size = 0;
    session_map->value_size = 0;

    if (pr_map->fd < 0) {
        fprintf(stderr, "map not opened\n");
        return EBADF;
    }
    if (pr_map->key_size != sizeof(uint32_t) || pr_map->value_size != sizeof(uint32_t)) {
        fprintf(stderr, "invalid session/group map\n");
        return EINVAL;
    }

    uint32_t inner_map_id = 0;
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

    ret = update_map_info(session_map);
    if (ret != NO_ERROR) {
        return ret;
    }

    if (session_map->key_size != sizeof(elem_t) || session_map->value_size != sizeof(struct element)) {
        fprintf(stderr, "invalid session/group inner map\n");
        return EINVAL;
    }

    return NO_ERROR;
}

static int do_create_pre_session(nikss_bpf_map_descriptor_t *pr_map,
                                 nikss_bpf_map_descriptor_t *session_template, uint32_t session, nikss_btf_t *btf)
{
    int error_code = 0;
    if (pr_map->fd < 0 || session_template->fd < 0) {
        fprintf(stderr, "maps not opened\n");
        return EBADF;
    }
    if (pr_map->key_size != sizeof(session)) {
        /* cppcheck-suppress invalidPrintfArgType_uint ; cppcheck failed to recognize a real type of size_t */
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
            .btf_fd = btf->btf_fd,
            .btf_key_type_id = session_template->map_key_type_id,
            .btf_value_type_id = session_template->map_value_type_id,
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
    uint64_t flags = BPF_NOEXIST;
    if (pr_map->type == BPF_MAP_TYPE_ARRAY_OF_MAPS) {
        flags = BPF_ANY;
    }
    error_code = bpf_map_update_elem(pr_map->fd, &session, &inner_map_fd, flags);
    if (error_code != 0) {
        error_code = errno;
        fprintf(stderr, "failed to add session/group to map: %s\n", strerror(error_code));
        goto ret;
    }

ret:
    close_object_fd(&inner_map_fd);
    return error_code;
}

static int create_pre_session(nikss_context_t *ctx, const char *pr_map, const char *pr_map_inner, uint32_t session)
{
    if (ctx == NULL || session == 0) {
        fprintf(stderr, "invalid session/group or context\n");
        return EINVAL;
    }

    nikss_bpf_map_descriptor_t outer_map;
    nikss_bpf_map_descriptor_t inner_map;
    nikss_btf_t btf;
    init_btf(&btf);

    int ret = open_pr_maps(ctx, pr_map, pr_map_inner, &outer_map, &inner_map);
    if (ret != NO_ERROR) {
        goto err;
    }

    load_btf(ctx, &btf);
    ret = do_create_pre_session(&outer_map, &inner_map, session, &btf);
    free_btf(&btf);

    if (ret != NO_ERROR) {
        fprintf(stderr, "failed to create session/group: %s\n", strerror(ret));
    }

err:
    close_object_fd(&inner_map.fd);
    close_object_fd(&outer_map.fd);
    return ret;
}

static int remove_pre_session(nikss_context_t *ctx, const char *pr_map_name, uint32_t session)
{
    if (ctx == NULL) {
        return EINVAL;
    }
    if (session == 0) {
        fprintf(stderr, "invalid session/group id\n");
        return EINVAL;
    }

    nikss_bpf_map_descriptor_t pr_map;

    int ret = open_pr_maps(ctx, pr_map_name, NULL, &pr_map, NULL);
    if (ret != 0) {
        goto err;
    }

    if (pr_map.key_size != sizeof(session)) {
        /* cppcheck-suppress invalidPrintfArgType_uint ; cppcheck failed to recognize a real type of size_t */
        fprintf(stderr, "key map size must be equal to %lu\n", sizeof(session));
        ret = EINVAL;
        goto err;
    }

    ret = bpf_map_delete_elem(pr_map.fd, &session);
    if (ret != 0) {
        ret = errno;
        fprintf(stderr, "failed to clear clone session with id %u: %s\n",
                session, strerror(ret));
        goto err;
    }

err:
    close_object_fd(&pr_map.fd);

    return ret;
}

static bool pre_session_exists(nikss_context_t *ctx, const char *pr_map_name, uint32_t session)
{
    if (ctx == NULL) {
        return false;
    }

    nikss_bpf_map_descriptor_t pr_map;
    int ret = open_pr_maps(ctx, pr_map_name, NULL, &pr_map, NULL);
    if (ret != 0) {
        return false;
    }

    if (pr_map.key_size != sizeof(uint32_t) || pr_map.value_size != sizeof(uint32_t)) {
        fprintf(stderr, "invalid session/group map\n");
        close_object_fd(&pr_map.fd);
        return false;
    }

    uint32_t inner_map_id = 0;
    ret = bpf_map_lookup_elem(pr_map.fd, &session, &inner_map_id);
    close_object_fd(&pr_map.fd);

    if (ret != 0) {
        return false;
    }

    return inner_map_id != 0;
}

static int pre_session_insert_entry(nikss_context_t *ctx, const char *pr_map_name,
                                    uint32_t session, nikss_clone_session_entry_t *entry)
{
    if (ctx == NULL || entry == NULL) {
        return EINVAL;
    }
    if (entry->instance == 0 && entry->egress_port == 0) {
        fprintf(stderr, "instance and egress port not set\n");
        return EINVAL;
    }

    nikss_bpf_map_descriptor_t session_map;
    nikss_bpf_map_descriptor_t pr_map;
    int ret = NO_ERROR;

    ret = open_pr_maps(ctx, pr_map_name, NULL, &pr_map, NULL);
    if (ret != 0) {
        return ret;
    }

    ret = open_session_map(&pr_map, &session_map, session);
    if (ret != NO_ERROR) {
        goto err;
    }

    if (session_map.key_size != sizeof(elem_t) || session_map.value_size != sizeof(struct element)) {
        fprintf(stderr, "invalid session/group inner map\n");
        goto err;
    }

    /* 1. Gead head. */
    elem_t head_idx = { 0 };
    struct element head;
    ret = bpf_map_lookup_elem(session_map.fd, &head_idx, &head);
    if (ret != 0) {
        ret = errno;
        fprintf(stderr, "error getting head of list: %s\n", strerror(ret));
        goto err;
    }

    /* 2. Allocate new element and put in the data. */
    struct element new_node_value = {
            .entry = *entry,
            /* 3. Make next of new node as next of head */
            .next_id = head.next_id,
    };
    elem_t new_node_key = {
            .port = entry->egress_port,
            .instance = entry->instance,
    };
    ret = bpf_map_update_elem(session_map.fd, &new_node_key, &new_node_value, BPF_NOEXIST);
    if (ret != 0) {
        ret = errno;
        if (ret == EEXIST) {
            fprintf(stderr, "Clone session/multicast member [port=%u, instance=%d] already exists. "
                            "Increment 'instance' to clone more than one packet to the same port.\n",
                    entry->egress_port,
                    entry->instance);
        } else if (ret < 0) {
            printf("error creating list element: %s\n", strerror(ret));
        }
        goto err;
    }

    /* 4. move the head to point to the new node */
    head.next_id = new_node_key;
    ret = bpf_map_update_elem(session_map.fd, &head_idx, &head, 0);
    if (ret < 0) {
        ret = errno;
        printf("error updating head: %s\n", strerror(ret));
        goto err;
    }

err:
    close_object_fd(&pr_map.fd);
    close_object_fd(&session_map.fd);

    return ret;
}

static int pre_session_del_entry(nikss_context_t *ctx, const char *pr_map_name,
                                 uint32_t session, nikss_clone_session_entry_t *entry)
{
    if (ctx == NULL || entry == NULL) {
        return EINVAL;
    }
    if (entry->instance == 0 && entry->egress_port == 0) {
        fprintf(stderr, "instance and egress port not set\n");
        return EINVAL;
    }

    nikss_bpf_map_descriptor_t session_map;
    nikss_bpf_map_descriptor_t pr_map;
    int ret = NO_ERROR;

    ret = open_pr_maps(ctx, pr_map_name, NULL, &pr_map, NULL);
    if (ret != 0) {
        return ret;
    }

    ret = open_session_map(&pr_map, &session_map, session);
    if (ret != NO_ERROR) {
        goto err;
    }

    if (session_map.key_size != sizeof(elem_t) || session_map.value_size != sizeof(struct element)) {
        ret = EINVAL;
        fprintf(stderr, "invalid session/group inner map\n");
        goto err;
    }

    /* Find previous node */
    elem_t prev_elem_key = { 0 };
    struct element prev_elem_value;
    bool found = false;
    do {
        ret = bpf_map_lookup_elem(session_map.fd, &prev_elem_key, &prev_elem_value);
        if (ret != 0) {
            ret = errno;
            break;
        }

        if (prev_elem_value.next_id.instance == entry->instance &&
            prev_elem_value.next_id.port == entry->egress_port) {
            found = true;
            break;
        }
        prev_elem_key = prev_elem_value.next_id;
    } while (prev_elem_value.next_id.port != 0 && prev_elem_value.next_id.instance != 0);

    if (ret != 0 || found == false) {
        if (ret == NO_ERROR) {
            ret = ENOENT;
        }
        fprintf(stderr, "error getting element from list (egress_port=%u, instance=%d): %s\n",
                entry->egress_port, entry->instance, strerror(ret));
        goto err;
    }

    /* Get node to remove */
    struct element elem_to_delete;
    elem_t key_to_delete = {
            .instance = entry->instance,
            .port = entry->egress_port,
    };
    ret = bpf_map_lookup_elem(session_map.fd, &key_to_delete, &elem_to_delete);
    if (ret != 0) {
        ret = errno;
        fprintf(stderr, "error getting element to delete: %s\n", strerror(ret));
        goto err;
    }

    /* Update previous node to point to next node */
    prev_elem_value.next_id = elem_to_delete.next_id;
    ret = bpf_map_update_elem(session_map.fd, &prev_elem_key, &prev_elem_value, BPF_EXIST);
    if (ret != 0) {
        ret = errno;
        fprintf(stderr, "failed to update previous element: %s\n", strerror(ret));
        goto err;
    }

    /* Remove node */
    ret = bpf_map_delete_elem(session_map.fd, &key_to_delete);
    if (ret != 0) {
        ret = errno;
        fprintf(stderr, "failed to delete element: %s\n", strerror(ret));
        goto err;
    }

err:
    close_object_fd(&session_map.fd);
    close_object_fd(&pr_map.fd);

    return ret;
}

static int pre_get_next_entry(nikss_context_t *ctx,
                              nikss_bpf_map_descriptor_t *session_map, const char *pr_map_name,
                              uint32_t session, uint32_t *current_egress_port, uint16_t *current_instance,
                              nikss_clone_session_entry_t *current_entry)
{
    if (ctx == NULL || session == 0) {
        fprintf(stderr, "invalid session/group or context\n");
        return EINVAL;
    }

    if (session_map->fd < 0) {
        nikss_bpf_map_descriptor_t pr_map;

        int ret = open_pr_maps(ctx, pr_map_name, NULL, &pr_map, NULL);
        if (ret != NO_ERROR) {
            return ret;
        }

        ret = open_session_map(&pr_map, session_map, session);
        close_object_fd(&pr_map.fd);
        if (ret != NO_ERROR) {
            return ret;
        }

        /* Start iteration from head */
        *current_egress_port = 0;
        *current_instance = 0;
    }

    /* Build key for current entry and read next key */
    elem_t key = {0};
    key.port = *current_egress_port;
    key.instance = *current_instance;
    struct element value;
    if (bpf_map_lookup_elem(session_map->fd, &key, &value) != 0) {
        fprintf(stderr, "failed to read next entry key: %s\n", strerror(errno));
        goto no_more_entries;
    }
    memcpy(&key, &value.next_id, sizeof(elem_t));

    /* Next entry exists? */
    if (key.port == 0 && key.instance == 0) {
        goto no_more_entries;
    }

    /* Read next entry */
    if (bpf_map_lookup_elem(session_map->fd, &key, &value) != 0) {
        fprintf(stderr, "failed to read next entry: %s", strerror(errno));
        goto no_more_entries;
    }
    memcpy(current_entry, &value.entry, sizeof(nikss_clone_session_entry_t));

    *current_egress_port = value.entry.egress_port;
    *current_instance = value.entry.instance;

    return NO_ERROR;

no_more_entries:
    *current_egress_port = 0;
    *current_instance = 0;
    return ENODATA;
}

static int pre_get_next_session(nikss_bpf_map_descriptor_t *pr_map, uint32_t *current_session_id)
{
    if (pr_map->fd < 0 ||
        pr_map->type != BPF_MAP_TYPE_ARRAY_OF_MAPS ||
        pr_map->key_size != 4 || pr_map->value_size != 4) {
        fprintf(stderr, "invalid sessions/groups map or not opened properly\n");
        return EINVAL;
    }

    /* This way is a little bit faster than using bpf_map_get_next_key
     * to scan all possible keys if we assume array map of maps type.
     * TODO: When kernel 5.19 or later will be in production, bpf_map_lookup_batch
     *       could be used to get list of groups and gain performance.
     *       See this commit: https://github.com/torvalds/linux/commit/9263dddc7b6f816fdd327eee435cc54ba51dd095
     *       To check kernel version at runtime see: https://stackoverflow.com/a/46282013 */
    uint32_t value = 0;
    while (true) {
        *current_session_id += 1;
        if (*current_session_id >= pr_map->max_entries) {
            *current_session_id = 0;
            return ENOENT;
        }

        if (bpf_map_lookup_elem(pr_map->fd, current_session_id, &value) == 0) {
            break;
        }
    }

    return NO_ERROR;
}

/******************************************************************************
 * Clone session
 ******************************************************************************/

void nikss_clone_session_context_init(nikss_clone_session_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    memset( ctx, 0, sizeof(nikss_clone_session_ctx_t));

    ctx->session_map.fd = -1;
}

void nikss_clone_session_context_free(nikss_clone_session_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    close_object_fd(&ctx->session_map.fd);
}

void nikss_clone_session_id(nikss_clone_session_ctx_t *ctx, nikss_clone_session_id_t id)
{
    if (ctx == NULL) {
        return;
    }
    ctx->id = id;

    /* Also reset session map if opened */
    close_object_fd(&ctx->session_map.fd);
}

nikss_clone_session_id_t nikss_clone_session_get_id(nikss_clone_session_ctx_t *ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    return ctx->id;
}

bool nikss_clone_session_exists(nikss_context_t *ctx, nikss_clone_session_ctx_t *session)
{
    if (session == NULL) {
        return false;
    }
    return pre_session_exists(ctx, CLONE_SESSION_TABLE, session->id);
}

int nikss_clone_session_create(nikss_context_t *ctx, nikss_clone_session_ctx_t *session)
{
    return create_pre_session(ctx, CLONE_SESSION_TABLE, CLONE_SESSION_TABLE_INNER, session->id);
}

void nikss_clone_session_entry_init(nikss_clone_session_entry_t *entry)
{
    if (entry == NULL) {
        return;
    }
    memset( entry, 0, sizeof(nikss_clone_session_entry_t));
}

void nikss_clone_session_entry_free(nikss_clone_session_entry_t *entry)
{
    if (entry == NULL) {
        return;
    }
    memset(entry, 0, sizeof(nikss_clone_session_entry_t));
}

void nikss_clone_session_entry_port(nikss_clone_session_entry_t *entry, uint32_t egress_port)
{
    entry->egress_port = egress_port;
}

uint32_t nikss_clone_session_entry_get_port(nikss_clone_session_entry_t *entry)
{
    if (entry == NULL) {
        return 0;
    }
    return entry->egress_port;
}

void nikss_clone_session_entry_instance(nikss_clone_session_entry_t *entry, uint16_t instance)
{
    entry->instance = instance;
}

uint16_t nikss_clone_session_entry_get_instance(nikss_clone_session_entry_t *entry)
{
    if (entry == NULL) {
        return 0;
    }
    return entry->instance;
}

void nikss_clone_session_entry_cos(nikss_clone_session_entry_t *entry, uint8_t class_of_service)
{
    entry->class_of_service = class_of_service;
}

uint8_t nikss_clone_session_entry_get_cos(nikss_clone_session_entry_t *entry)
{
    if (entry == NULL) {
        return 0;
    }
    return entry->class_of_service;
}

void nikss_clone_session_entry_truncate_enable(nikss_clone_session_entry_t *entry, uint16_t packet_length_bytes)
{
    entry->truncate = true;
    entry->packet_length_bytes = packet_length_bytes;
}

/* cppcheck-suppress unusedFunction ; public API call */
void nikss_clone_session_entry_truncate_disable(nikss_clone_session_entry_t *entry)
{
    entry->truncate = false;
    entry->packet_length_bytes = 0;
}

bool nikss_clone_session_entry_get_truncate_state(nikss_clone_session_entry_t *entry)
{
    if (entry == NULL) {
        return 0;
    }
    return entry->truncate != 0;
}

uint16_t nikss_clone_session_entry_get_truncate_length(nikss_clone_session_entry_t *entry)
{
    if (entry == NULL || entry->truncate == 0) {
        return 0;
    }
    return entry->packet_length_bytes;
}

int nikss_clone_session_entry_update(nikss_context_t *ctx, nikss_clone_session_ctx_t *session, nikss_clone_session_entry_t *entry)
{
    if (session == NULL) {
        return EINVAL;
    }

    return pre_session_insert_entry(ctx, CLONE_SESSION_TABLE, session->id, entry);
}

int nikss_clone_session_delete(nikss_context_t *ctx, nikss_clone_session_ctx_t *session)
{
    if (session == NULL) {
        return EINVAL;
    }

    return remove_pre_session(ctx, CLONE_SESSION_TABLE, session->id);
}

int nikss_clone_session_entry_delete(nikss_context_t *ctx, nikss_clone_session_ctx_t *session, nikss_clone_session_entry_t *entry)
{
    if (session == NULL) {
        return EINVAL;
    }
    return pre_session_del_entry(ctx, CLONE_SESSION_TABLE, session->id, entry);
}

/* cppcheck-suppress unusedFunction ; public API call */
int nikss_clone_session_entry_exists(nikss_context_t *ctx, nikss_clone_session_ctx_t *session, nikss_clone_session_entry_t *entry)
{
    (void) ctx; (void) session; (void) entry;
    return NO_ERROR;
}

nikss_clone_session_entry_t *nikss_clone_session_get_next_entry(nikss_context_t *ctx, nikss_clone_session_ctx_t *session)
{
    if (ctx == NULL || session == NULL) {
        fprintf(stderr, "invalid session or context\n");
        return NULL;
    }

    int ret = pre_get_next_entry(ctx, &session->session_map, CLONE_SESSION_TABLE,
                                 session->id,
                                 &session->current_egress_port, &session->current_instance,
                                 &session->current_entry);
    if (ret != NO_ERROR) {
        return NULL;
    }

    return &session->current_entry;
}

int nikss_clone_session_list_init(nikss_context_t *ctx, nikss_clone_session_list_t *list)
{
    if (ctx == NULL || list == NULL) {
        return EINVAL;
    }

    memset(list, 0, sizeof(nikss_clone_session_list_t));
    list->session_map.fd = -1;
    nikss_clone_session_context_init(&list->current_session);

    return open_pr_maps(ctx, CLONE_SESSION_TABLE, NULL, &list->session_map, NULL);
}

void nikss_clone_session_list_free(nikss_clone_session_list_t *list)
{
    if (list == NULL) {
        return;
    }

    close_object_fd(&list->session_map.fd);
    nikss_clone_session_context_free(&list->current_session);
}

nikss_clone_session_ctx_t *nikss_clone_session_list_get_next_group(nikss_clone_session_list_t *list)
{
    if (list == NULL) {
        return NULL;
    }

    if (pre_get_next_session(&list->session_map, &list->current_id) != NO_ERROR) {
        return NULL;
    }

    nikss_clone_session_context_init(&list->current_session);
    nikss_clone_session_id(&list->current_session, list->current_id);

    return &list->current_session;
}

/******************************************************************************
 * Multicast groups
 ******************************************************************************/

void nikss_mcast_grp_context_init(nikss_mcast_grp_ctx_t *group)
{
    if (group == NULL) {
        return;
    }
    memset(group, 0, sizeof(nikss_mcast_grp_ctx_t));

    group->group_map.fd = -1;
}

void nikss_mcast_grp_context_free(nikss_mcast_grp_ctx_t *group)
{
    if (group == NULL) {
        return;
    }

    close_object_fd(&group->group_map.fd);

    memset(group, 0, sizeof(nikss_mcast_grp_ctx_t));
    group->group_map.fd = -1;
}

void nikss_mcast_grp_id(nikss_mcast_grp_ctx_t *group, nikss_mcast_grp_id_t mcast_grp_id)
{
    if (group != NULL) {
        group->id = mcast_grp_id;
    }

    /* Also reset group map */
    close_object_fd(&group->group_map.fd);
}

nikss_mcast_grp_id_t nikss_mcast_grp_get_id(nikss_mcast_grp_ctx_t *group)
{
    if (group == NULL) {
        return 0;
    }

    return group->id;
}

int nikss_mcast_grp_create(nikss_context_t *ctx, nikss_mcast_grp_ctx_t *group)
{
    return create_pre_session(ctx, MULTICAST_GROUP_TABLE, MULTICAST_GROUP_TABLE_INNER, group->id);
}

bool nikss_mcast_grp_exists(nikss_context_t *ctx, nikss_mcast_grp_ctx_t *group)
{
    if (group == NULL) {
        return false;
    }
    return pre_session_exists(ctx, MULTICAST_GROUP_TABLE, group->id);
}

int nikss_mcast_grp_delete(nikss_context_t *ctx, nikss_mcast_grp_ctx_t *group)
{
    if (group == NULL) {
        return EINVAL;
    }

    return remove_pre_session(ctx, MULTICAST_GROUP_TABLE, group->id);
}

void nikss_mcast_grp_member_init(nikss_mcast_grp_member_t *member)
{
    if (member == NULL) {
        return;
    }
    memset(member, 0, sizeof(nikss_mcast_grp_member_t));
}

void nikss_mcast_grp_member_free(nikss_mcast_grp_member_t *member)
{
    if (member == NULL) {
        return;
    }
    memset(member, 0, sizeof(nikss_mcast_grp_member_t));
}

void nikss_mcast_grp_member_port(nikss_mcast_grp_member_t *member, uint32_t egress_port)
{
    if (member != NULL) {
        member->egress_port = egress_port;
    }
}

void nikss_mcast_grp_member_instance(nikss_mcast_grp_member_t *member, uint16_t instance)
{
    if (member != NULL) {
        member->instance = instance;
    }
}

uint32_t nikss_mcast_grp_member_get_port(nikss_mcast_grp_member_t *member)
{
    if (member == NULL) {
        return 0;
    }
    return member->egress_port;
}

uint16_t nikss_mcast_grp_member_get_instance(nikss_mcast_grp_member_t *member)
{
    if (member == NULL) {
        return 0;
    }
    return member->instance;
}

int nikss_mcast_grp_member_update(nikss_context_t *ctx, nikss_mcast_grp_ctx_t *group, nikss_mcast_grp_member_t *member)
{
    if (group == NULL || member == NULL) {
        return EINVAL;
    }

    nikss_clone_session_entry_t entry = {
            .egress_port = member->egress_port,
            .instance = member->instance,
    };

    return pre_session_insert_entry(ctx, MULTICAST_GROUP_TABLE, group->id, &entry);
}

/* cppcheck-suppress unusedFunction ; public API call */
int nikss_mcast_grp_member_exists(nikss_context_t *ctx, nikss_mcast_grp_ctx_t *group, nikss_mcast_grp_member_t *member)
{
    (void) ctx; (void) group; (void) member;
    return NO_ERROR;
}

int nikss_mcast_grp_member_delete(nikss_context_t *ctx, nikss_mcast_grp_ctx_t *group, nikss_mcast_grp_member_t *member)
{
    if (group == NULL || member == NULL) {
        return EINVAL;
    }

    nikss_clone_session_entry_t entry = {
            .egress_port = member->egress_port,
            .instance = member->instance,
    };

    return pre_session_del_entry(ctx, MULTICAST_GROUP_TABLE, group->id, &entry);
}

nikss_mcast_grp_member_t *nikss_mcast_grp_get_next_member(nikss_context_t *ctx, nikss_mcast_grp_ctx_t *group)
{
    if (ctx == NULL || group == NULL) {
        fprintf(stderr, "invalid group or context\n");
        return NULL;
    }

    nikss_clone_session_entry_t entry= {};
    int ret = pre_get_next_entry(ctx, &group->group_map, MULTICAST_GROUP_TABLE,
                                 group->id,
                                 &group->current_egress_port, &group->current_instance,
                                 &entry);
    if (ret != NO_ERROR) {
        return NULL;
    }

    group->current_member.egress_port = entry.egress_port;
    group->current_member.instance = entry.instance;

    return &group->current_member;
}

int nikss_mcast_grp_list_init(nikss_context_t *ctx, nikss_mcast_grp_list_t *list)
{
    if (ctx == NULL || list == NULL) {
        return EINVAL;
    }

    memset(list, 0, sizeof(nikss_mcast_grp_list_t));
    list->group_map.fd = -1;
    nikss_mcast_grp_context_init(&list->current_group);

    return open_pr_maps(ctx, MULTICAST_GROUP_TABLE, NULL, &list->group_map, NULL);
}

void nikss_mcast_grp_list_free(nikss_mcast_grp_list_t *list)
{
    if (list == NULL) {
        return;
    }

    close_object_fd(&list->group_map.fd);
    nikss_mcast_grp_context_free(&list->current_group);
}

nikss_mcast_grp_ctx_t *nikss_mcast_grp_list_get_next_group(nikss_mcast_grp_list_t *list)
{
    if (list == NULL) {
        return NULL;
    }

    if (pre_get_next_session(&list->group_map, &list->current_id) != NO_ERROR) {
        return NULL;
    }

    nikss_mcast_grp_context_init(&list->current_group);
    nikss_mcast_grp_id(&list->current_group, list->current_id);

    return &list->current_group;
}
