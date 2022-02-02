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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>

#include "../include/psabpf.h"
#include "btf.h"
#include "common.h"
#include "psabpf_table.h"

static int open_group_map(psabpf_action_selector_context_t *ctx,
                          psabpf_action_selector_group_context_t *group)
{
    if (ctx->map_of_groups.fd < 0) {
        fprintf(stderr, "map of groups not opened\n");
        return EINVAL;
    }
    if (ctx->map_of_groups.key_size != 4 || ctx->map_of_groups.value_size != 4) {
        fprintf(stderr, "invalid map of groups\n");
        return EINVAL;
    }

    uint32_t inner_map_id = 0;
    int err = bpf_map_lookup_elem(ctx->map_of_groups.fd, &group->group_ref, &inner_map_id);
    if (err != 0) {
        fprintf(stderr, "group %u was not found\n", group->group_ref);
        return ENOENT;
    }
    ctx->group.fd = bpf_map_get_fd_by_id(inner_map_id);
    if (ctx->group.fd < 0) {
        fprintf(stderr, "group map for group %u was not found\n", group->group_ref);
        return ENOENT;
    }

    return NO_ERROR;
}

static int get_number_of_members_in_group(psabpf_action_selector_context_t *ctx, uint32_t *number_of_members) {
    uint32_t key = 0;
    int return_code = bpf_map_lookup_elem(ctx->group.fd, &key, number_of_members);
    if (return_code != 0) {
        return_code = errno;
        fprintf(stderr, "failed to obtain number of members in group: %s\n", strerror(return_code));
        return return_code;
    }
    return NO_ERROR;
}

static int update_number_of_members_in_group(psabpf_action_selector_context_t *ctx, uint32_t new_value) {
    uint32_t key = 0;
    int return_code = bpf_map_update_elem(ctx->group.fd, &key, &new_value, BPF_ANY);
    if (return_code != 0) {
        return_code = errno;
        fprintf(stderr, "failed to update member in group: %s\n", strerror(return_code));
        return return_code;
    }
    return NO_ERROR;
}

static uint32_t find_member_entry_idx_in_group(psabpf_bpf_map_descriptor_t *group,
                                               uint32_t number_of_members,
                                               psabpf_action_selector_member_context_t *member)
{
    for (uint32_t index = 1; index <= number_of_members; ++index) {
        uint32_t current_member_ref;
        int return_code = bpf_map_lookup_elem(group->fd, &index, &current_member_ref);
        if (return_code == 0 && current_member_ref == member->member_ref) {
            return index;
        }
    }
    return 0;
}

static bool validate_member_reference(psabpf_action_selector_context_t *ctx,
                                      psabpf_action_selector_member_context_t *member)
{
    char *value = malloc(ctx->map_of_members.value_size);
    if (value == NULL)
        return false;

    int ret = bpf_map_lookup_elem(ctx->map_of_members.fd, &member->member_ref, value);
    free(value);

    if (ret != 0)
        return false;
    return true;
}

void psabpf_action_selector_ctx_init(psabpf_action_selector_context_t *ctx)
{
    if (ctx == NULL)
        return;
    memset(ctx, 0, sizeof(*ctx));

    /* 0 is a valid file descriptor */
    ctx->btf.associated_prog = -1;
    ctx->group.fd = -1;
    ctx->map_of_groups.fd = -1;
    ctx->map_of_members.fd = -1;
    ctx->default_group_action.fd = -1;
    ctx->cache.fd = -1;
}

void psabpf_action_selector_ctx_free(psabpf_action_selector_context_t *ctx)
{
    if (ctx == NULL)
        return;

    free_btf(&ctx->btf);

    close_object_fd(&ctx->group.fd);
    close_object_fd(&ctx->map_of_groups.fd);
    close_object_fd(&ctx->map_of_members.fd);
    close_object_fd(&ctx->default_group_action.fd);
    close_object_fd(&ctx->cache.fd);
}

static int do_open_action_selector(psabpf_context_t *psabpf_ctx, psabpf_action_selector_context_t *ctx, const char *name)
{
    int ret;
    char derived_name[256];

    snprintf(derived_name, sizeof(derived_name), "%s_groups_inner", name);
    ret = open_bpf_map(psabpf_ctx, derived_name, &ctx->btf, &ctx->group);
    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't open map %s: %s\n", derived_name, strerror(ret));
        return ret;
    }
    close_object_fd(&ctx->group.fd);

    snprintf(derived_name, sizeof(derived_name), "%s_groups", name);
    ret = open_bpf_map(psabpf_ctx, derived_name, &ctx->btf, &ctx->map_of_groups);
    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't open map %s: %s\n", derived_name, strerror(ret));
        return ret;
    }

    snprintf(derived_name, sizeof(derived_name), "%s_actions", name);
    ret = open_bpf_map(psabpf_ctx, derived_name, &ctx->btf, &ctx->map_of_members);
    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't open map %s: %s\n", derived_name, strerror(ret));
        return ret;
    }

    snprintf(derived_name, sizeof(derived_name), "%s_defaultActionGroup", name);
    ret = open_bpf_map(psabpf_ctx, derived_name, &ctx->btf, &ctx->default_group_action);
    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't open map %s: %s\n", derived_name, strerror(ret));
        return ret;
    }

    snprintf(derived_name, sizeof(derived_name), "%s_cache", name);
    ret = open_bpf_map(psabpf_ctx, derived_name, &ctx->btf, &ctx->cache);
    if (ret != NO_ERROR) {
        fprintf(stderr, "warning: couldn't find ActionSelector cache: %s\n", strerror(ret));
    }

    return NO_ERROR;
}

int psabpf_action_selector_ctx_open(psabpf_context_t *psabpf_ctx, psabpf_action_selector_context_t *ctx, const char *name)
{
    if (ctx == NULL || psabpf_ctx == NULL || name == NULL)
        return EINVAL;

    /* get the BTF, it is optional so print only warning */
    if (load_btf(psabpf_ctx, &ctx->btf) != NO_ERROR)
        fprintf(stderr, "warning: couldn't find BTF info\n");

    int ret = do_open_action_selector(psabpf_ctx, ctx, name);
    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't open ActionSelector %s: %s\n", name, strerror(ret));
        return ret;
    }

    return NO_ERROR;
}

void psabpf_action_selector_member_init(psabpf_action_selector_member_context_t *member)
{
    if (member == NULL)
        return;

    memset(member, 0, sizeof(*member));
    psabpf_action_init(&member->action);
}

void psabpf_action_selector_member_free(psabpf_action_selector_member_context_t *member)
{
    if (member == NULL)
        return;

    psabpf_action_free(&member->action);
}

void psabpf_action_selector_group_init(psabpf_action_selector_group_context_t *group)
{
    if (group == NULL)
        return;

    memset(group, 0, sizeof(*group));
}

void psabpf_action_selector_group_free(psabpf_action_selector_group_context_t *group)
{
    (void) group;
}

int psabpf_action_selector_member_action(psabpf_action_selector_member_context_t *member, psabpf_action_t *action)
{
    if (member == NULL || action == NULL)
        return EINVAL;

    move_action(&member->action, action);
    return NO_ERROR;
}

uint32_t psabpf_action_selector_get_member_reference(psabpf_action_selector_member_context_t *member)
{
    if (member == NULL)
        return PSABPF_ACTION_SELECTOR_INVALID_REFERENCE;
    return member->member_ref;
}

void psabpf_action_selector_set_member_reference(psabpf_action_selector_member_context_t *member, uint32_t member_ref)
{
    if (member == NULL)
        return;
    member->member_ref = member_ref;
}

uint32_t psabpf_action_selector_get_group_reference(psabpf_action_selector_group_context_t *group)
{
    if (group == NULL)
        return PSABPF_ACTION_SELECTOR_INVALID_REFERENCE;
    return group->group_ref;
}

void psabpf_action_selector_set_group_reference(psabpf_action_selector_group_context_t *group, uint32_t group_ref)
{
    if (group == NULL)
        return;
    group->group_ref = group_ref;
}

static uint32_t find_and_reserve_reference(psabpf_bpf_map_descriptor_t *map, void *data)
{
    uint32_t ref;
    if (map->key_size != 4) {
        fprintf(stderr, "expected that map have 32 bit key\n");
        return PSABPF_ACTION_SELECTOR_INVALID_REFERENCE;
    }
    if (map->fd < 0) {
        fprintf(stderr, "map not opened\n");
        return PSABPF_ACTION_SELECTOR_INVALID_REFERENCE;
    }

    char *value = malloc(map->value_size);
    if (value == NULL) {
        fprintf(stderr, "not enough memory\n");
        return PSABPF_ACTION_SELECTOR_INVALID_REFERENCE;
    }
    if (data != NULL)
        memcpy(value, data, map->value_size);
    else
        memset(value, 0, map->value_size);

    bool found = false;
    for (ref = 1; ref <= map->max_entries; ++ref) {
        int return_code = bpf_map_update_elem(map->fd, &ref, value, BPF_NOEXIST);
        if (return_code == 0) {
            found = true;
            break;
        }
    }
    free(value);

    if (found == true)
        return ref;
    return PSABPF_ACTION_SELECTOR_INVALID_REFERENCE;
}

int psabpf_action_selector_add_member(psabpf_action_selector_context_t *ctx, psabpf_action_selector_member_context_t *member)
{
    if (ctx == NULL || member == NULL)
        return EINVAL;
    if (ctx->map_of_members.fd < 0) {
        fprintf(stderr, "Map of members not opened\n");
        return EINVAL;
    }

    member->member_ref = find_and_reserve_reference(&ctx->map_of_members, NULL);
    if (member->member_ref == PSABPF_ACTION_SELECTOR_INVALID_REFERENCE) {
        fprintf(stderr, "failed to find available reference for member");
        return EFBIG;  /* Probably, here we know we have access to eBPF, so most probably version is that map is full */
    }

    int ret = psabpf_action_selector_update_member(ctx, member);
    if (ret != NO_ERROR) {
        /* Remove reserved reference if failed to add */
        bpf_map_delete_elem(ctx->map_of_members.fd, &member->member_ref);
        return ret;
    }

    return ret;
}

int psabpf_action_selector_update_member(psabpf_action_selector_context_t *ctx, psabpf_action_selector_member_context_t *member)
{
    if (ctx == NULL || member == NULL)
        return EINVAL;
    if (ctx->map_of_members.fd < 0) {
        fprintf(stderr, "Map of members not opened\n");
        return EINVAL;
    }

    /* Let's go the simplest way - abuse (little) table API. Don't do this at home! */
    psabpf_table_entry_ctx_t tec = {
            .table = ctx->map_of_members,
            .btf_metadata = ctx->btf,
            .cache = ctx->cache,  /* Allow clear cache if applicable */
    };
    psabpf_match_key_t mk[] = {
            {
                    .type = PSABPF_EXACT,
                    .key_size = sizeof(member->member_ref),
                    .data = &member->member_ref,
            },
    };
    psabpf_match_key_t * mk_ptr = &(mk[0]);
    psabpf_table_entry_t te = {
            .action = &member->action,
            .match_keys = &mk_ptr,
            .n_keys = 1,
    };

    /* Will also clear cache */
    return psabpf_table_entry_update(&tec, &te);
}

static bool member_in_use(psabpf_action_selector_context_t *ctx, psabpf_action_selector_member_context_t *member)
{
    bool found = false;
    uint32_t key = 0, next_key;

    /* Iterate over every group and check if member reference exists */
    if (bpf_map_get_next_key(ctx->map_of_groups.fd, NULL, &next_key) != 0)
        return false;  /* no groups */
    do {
        /* Swap buffers, so next_key will become key and next_key may be reused */
        uint32_t tmp_key = next_key;
        next_key = key;
        key = tmp_key;

        /* Get group */
        psabpf_action_selector_group_context_t group;
        group.group_ref = key;
        if (open_group_map(ctx, &group) != NO_ERROR)
            continue;

        /* Try to find member in a current group */
        uint32_t number_of_members = 0;
        if (get_number_of_members_in_group(ctx, &number_of_members) == NO_ERROR) {
            if (find_member_entry_idx_in_group(&ctx->group, number_of_members, member) != 0) {
                fprintf(stderr, "%u referenced in group %u\n", member->member_ref, group.group_ref);
                found = true;
            }
        }
        close_object_fd(&ctx->group.fd);
    } while (bpf_map_get_next_key(ctx->map_of_groups.fd, &key, &next_key) == 0 && !found);

    return found;
}

int psabpf_action_selector_del_member(psabpf_action_selector_context_t *ctx, psabpf_action_selector_member_context_t *member)
{
    if (ctx == NULL || member == NULL)
        return EINVAL;
    if (ctx->map_of_members.fd < 0) {
        fprintf(stderr, "Map of members not opened\n");
        return EINVAL;
    }
    if (ctx->map_of_members.key_size != 4) {
        fprintf(stderr, "expected that map have 32 bit key\n");
        return EINVAL;
    }
    if (ctx->group.key_size != 4 || ctx->group.value_size != 4) {
        fprintf(stderr, "invalid group map\n");
        return EINVAL;
    }

    /* Validate if member is referenced in any group */
    if (member_in_use(ctx, member)) {
        fprintf(stderr, "failed to delete member %u: already in use\n", member->member_ref);
        return EBUSY;
    }

    int ret = bpf_map_delete_elem(ctx->map_of_members.fd, &member->member_ref);
    if (ret != 0) {
        ret = errno;
        fprintf(stderr, "failed to delete member %u: %s\n", member->member_ref, strerror(ret));
        return ret;
    }

    ret = clear_table_cache(&ctx->cache);
    if (ret != NO_ERROR) {
        fprintf(stderr, "failed to clear cache: %s\n", strerror(ret));
    }

    return NO_ERROR;
}

int psabpf_action_selector_add_group(psabpf_action_selector_context_t *ctx, psabpf_action_selector_group_context_t *group)
{
    if (ctx == NULL || group == NULL)
        return EINVAL;
    if (ctx->map_of_groups.fd < 0) {
        fprintf(stderr, "Map of groups not opened\n");
        return EINVAL;
    }
    if (ctx->group.fd >= 0) {
        fprintf(stderr, "Group map not closed properly before\n");
        return EINVAL;
    }
    if (ctx->group.key_size != 4 || ctx->group.value_size != 4) {
        fprintf(stderr, "invalid group map\n");
        return EINVAL;
    }

    struct bpf_create_map_attr attr = {
            .key_size = ctx->group.key_size,
            .value_size = ctx->group.value_size,
            .max_entries = ctx->group.max_entries,
            .map_type = ctx->group.type,
    };
    ctx->group.fd = bpf_create_map_xattr(&attr);
    if (ctx->group.fd < 0) {
        int err = errno;
        fprintf(stderr, "failed to create new group: %s\n", strerror(err));
        return err;
    }

    group->group_ref = find_and_reserve_reference(&ctx->map_of_groups, &ctx->group.fd);
    /* Group is no more needed, restore ctx to its original state */
    close_object_fd(&ctx->group.fd);

    if (group->group_ref == PSABPF_ACTION_SELECTOR_INVALID_REFERENCE) {
        fprintf(stderr, "failed to insert new group to map of groups\n");
        return EFBIG;
    }

    return NO_ERROR;
}

int psabpf_action_selector_del_group(psabpf_action_selector_context_t *ctx, psabpf_action_selector_group_context_t *group)
{
    if (ctx == NULL || group == NULL)
        return EINVAL;
    if (ctx->map_of_groups.fd < 0) {
        fprintf(stderr, "Map of groups not opened\n");
        return EINVAL;
    }

    int ret = bpf_map_delete_elem(ctx->map_of_groups.fd, &group->group_ref);
    if (ret != 0) {
        ret = errno;
        fprintf(stderr, "failed to delete group %u: %s\n", group->group_ref, strerror(ret));
        return ret;
    }

    ret = clear_table_cache(&ctx->cache);
    if (ret != NO_ERROR) {
        fprintf(stderr, "failed to clear cache: %s\n", strerror(ret));
    }

    return NO_ERROR;
}

static int append_member_to_group(psabpf_action_selector_context_t *ctx,
                                  psabpf_action_selector_member_context_t *member)
{
    if (ctx->group.key_size != 4 || ctx->group.value_size != 4 || ctx->group.fd < 0)
        return EINVAL;

    uint32_t group_key;
    uint32_t number_of_members;
    int return_code;

    /* Get number of members. */
    if (get_number_of_members_in_group(ctx, &number_of_members) != NO_ERROR)
        return EPERM;

    /* Verify that member reference not existed in group before */
    if (find_member_entry_idx_in_group(&ctx->group, number_of_members, member) != 0) {
        fprintf(stderr, "%u already exists in group\n", member->member_ref);
        return EEXIST;
    }

    /* Append new member if possible */
    group_key = number_of_members + 1;
    return_code = bpf_map_update_elem(ctx->group.fd, &group_key, &member->member_ref, BPF_ANY);
    if (return_code != 0) {
        return_code = errno;
        fprintf(stderr, "failed to add member to group: %s\n", strerror(return_code));
        return return_code;
    }

    /* Register new member - increase number of members */
    return_code = update_number_of_members_in_group(ctx, number_of_members + 1);
    if (return_code != NO_ERROR)
        return return_code;

    return NO_ERROR;
}

int psabpf_action_selector_add_member_to_group(psabpf_action_selector_context_t *ctx,
                                               psabpf_action_selector_group_context_t *group,
                                               psabpf_action_selector_member_context_t *member)
{
    int return_code;

    if (ctx == NULL || group == NULL || member == NULL)
        return EINVAL;
    if (ctx->group.key_size != 4 || ctx->group.value_size != 4) {
        fprintf(stderr, "invalid group map\n");
        return EINVAL;
    }
    if (ctx->group.fd >= 0) {
        fprintf(stderr, "group map not closed properly before\n");
        return EINVAL;
    }

    /* verify that member reference exists and is valid */
    if (!validate_member_reference(ctx, member)) {
        fprintf(stderr, "invalid member reference: %u\n", member->member_ref);
        return EINVAL;
    }

    return_code = open_group_map(ctx, group);
    if (return_code != NO_ERROR)
        return return_code;

    return_code = append_member_to_group(ctx, member);
    close_object_fd(&ctx->group.fd);
    if (return_code != NO_ERROR)
        return return_code;

    return_code = clear_table_cache(&ctx->cache);
    if (return_code != NO_ERROR) {
        fprintf(stderr, "failed to clear cache: %s\n", strerror(return_code));
    }

    return return_code;
}

static int remove_member_from_group(psabpf_action_selector_context_t *ctx,
                                    psabpf_action_selector_member_context_t *member)
{
    if (ctx->group.key_size != 4 || ctx->group.value_size != 4 || ctx->group.fd < 0)
        return EINVAL;
    if (member->member_ref == PSABPF_ACTION_SELECTOR_INVALID_REFERENCE)
        return EINVAL;

    int return_code;
    uint32_t number_of_members;
    uint32_t index_to_remove;
    uint32_t last_member_ref;

    /* 1. Find out number of members */
    if (get_number_of_members_in_group(ctx, &number_of_members) != NO_ERROR)
        return EPERM;

    /* 2. Find index of our reference */
    index_to_remove = find_member_entry_idx_in_group(&ctx->group, number_of_members, member);
    if (index_to_remove == 0) {
        fprintf(stderr, "%u not referenced in group\n", member->member_ref);
        return ENOENT;
    }

    /* 3. Find reference of last member in group (see comment below) */
    return_code = bpf_map_lookup_elem(ctx->group.fd, &number_of_members, &last_member_ref);
    if (return_code != 0) {
        return_code = errno;
        fprintf(stderr, "failed to get last member in a group: %s\n", strerror(return_code));
        return return_code;
    }

    /* 4. Make map batch update great again!
     * Let's remove member from group in a single system call. This should ensure the shortest
     * possible time when there is inconsistency in a group structure causing strange behaviour.
     * This is due to the fact that kernel code should not be preempted. The only way (RT kernel
     * not including to this) to observe incorrect behaviour is to process packets on the other
     * CPU core. Summarize what we know at this point:
     *   - (0, number_of_members) - number of members
     *   - (index_to_remove, member->member_ref) - member which we want to remove
     *   - (number_of_members, last_member_ref) - last member in group which will be placed instead of removed member
     * So, we should update group with following entries in these order:
     *   - (index_to_remove, last_member_ref) - move last member to inside the list (for now there is two instances of this member)
     *   - (0, number_of_members - 1) - make the end of the list unused now
     *   - (number_of_members, 0) - prune unused value
     * If removed member is last member in group, we should skip first line in above recipe.
     */
    DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
                        .elem_flags = 0,
                        .flags = 0,
    );
    uint32_t keys[3] =   { index_to_remove, 0,                     number_of_members };
    uint32_t values[3] = { last_member_ref, number_of_members - 1, 0 };
    uint32_t n_keys = 3;
    if (index_to_remove == number_of_members)
        n_keys = 2;
    return_code = bpf_map_update_batch(ctx->group.fd, &(keys[3-n_keys]), &(values[3-n_keys]), &n_keys, &opts);
    if (return_code != 0) {
        return_code = errno;
        fprintf(stderr, "failed to remove member from group: %s\n", strerror(return_code));
        return return_code;
    }

    return NO_ERROR;
}

int psabpf_action_selector_del_member_from_group(psabpf_action_selector_context_t *ctx,
                                                 psabpf_action_selector_group_context_t *group,
                                                 psabpf_action_selector_member_context_t *member)
{
    int return_code;

    if (ctx == NULL || group == NULL || member == NULL)
        return EINVAL;
    if (ctx->group.key_size != 4 || ctx->group.value_size != 4) {
        fprintf(stderr, "invalid group map\n");
        return EINVAL;
    }
    if (ctx->group.fd >= 0) {
        fprintf(stderr, "group map not closed properly before\n");
        return EINVAL;
    }

    if (member->member_ref == PSABPF_ACTION_SELECTOR_INVALID_REFERENCE) {
        fprintf(stderr, "invalid member reference\n");
        return EINVAL;
    }

    return_code = open_group_map(ctx, group);
    if (return_code != NO_ERROR)
        return return_code;

    return_code = remove_member_from_group(ctx, member);

    close_object_fd(&ctx->group.fd);

    if (return_code != NO_ERROR)
        return return_code;

    return_code = clear_table_cache(&ctx->cache);
    if (return_code != NO_ERROR) {
        fprintf(stderr, "failed to clear cache: %s\n", strerror(return_code));
    }

    return NO_ERROR;
}

int psabpf_action_selector_set_default_group_action(psabpf_action_selector_context_t *ctx, psabpf_action_t *action)
{
    if (ctx == NULL || action == NULL)
        return EINVAL;
    if (ctx->default_group_action.fd < 0) {
        fprintf(stderr, "map with default action for empty group not opened\n");
        return EINVAL;
    }
    if (ctx->default_group_action.key_size != 4) {
        fprintf(stderr, "invalid map with default action form empty group\n");
        return EINVAL;
    }
    uint32_t key = 0;

    /* Let's again abuse (little) table API. Don't do this at home! */
    psabpf_table_entry_ctx_t tec = {
            .table = ctx->default_group_action,
            .btf_metadata = ctx->btf,
            .cache = ctx->cache,  /* Allow clear cache if applicable */
    };
    psabpf_match_key_t mk[] = {
            {
                    .type = PSABPF_EXACT,
                    .key_size = sizeof(key),
                    .data = &key,
            },
    };
    psabpf_match_key_t * mk_ptr = &(mk[0]);
    psabpf_table_entry_t te = {
            .action = action,
            .match_keys = &mk_ptr,
            .n_keys = 1,
    };

    /* Will also clear cache */
    return psabpf_table_entry_update(&tec, &te);
}
