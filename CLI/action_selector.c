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
#include <errno.h>
#include <jansson.h>

#include "common.h"
#include "action_selector.h"

/******************************************************************************
 * Command line parsing functions
 *****************************************************************************/

static int parse_dst_action_selector(int *argc, char ***argv, psabpf_context_t *psabpf_ctx,
                                     psabpf_action_selector_context_t *ctx, bool is_last, const char **instance_name)
{
    int error_code = psabpf_action_selector_ctx_name(psabpf_ctx, ctx, **argv);
    if (error_code != NO_ERROR)
        return error_code;

    if (instance_name)
        *instance_name = **argv;

    if (is_last) {
        NEXT_ARGP();
    } else {
        NEXT_ARGP_RET();
    }

    return NO_ERROR;
}

static int parse_action_selector_action(int *argc, char ***argv, psabpf_action_selector_context_t *ctx,
                                        psabpf_action_t *action)
{
    if (!is_keyword(**argv, "action")) {
        fprintf(stderr, "%s: expected keyword \'action\'\n", **argv);
        return EINVAL;
    }
    NEXT_ARGP_RET();

    if (is_keyword(**argv, "id")) {
        NEXT_ARGP_RET();
        char *ptr;
        psabpf_action_set_id(action, strtoul(**argv, &ptr, 0));
        if (*ptr) {
            fprintf(stderr, "%s: unable to parse as an action id\n", **argv);
            return EINVAL;
        }
    } else if (is_keyword(**argv, "name")) {
        NEXT_ARGP_RET();
        uint32_t action_id = psabpf_action_selector_get_action_id_by_name(ctx, **argv);
        if (action_id == PSABPF_INVALID_ACTION_ID) {
            fprintf(stderr, "%s: action not found\n", **argv);
            return EINVAL;
        }
        psabpf_action_set_id(action, action_id);
    } else {
        fprintf(stderr, "%s: unknown action specification\n", **argv);
        return EINVAL;
    }

    NEXT_ARGP();

    return NO_ERROR;
}

static int parse_action_data(int *argc, char ***argv, psabpf_action_t *action)
{
    if (!is_keyword(**argv, "data")) {
        return NO_ERROR;
    }

    do {
        NEXT_ARGP_RET();

        psabpf_action_param_t param;
        int error_code = translate_data_to_bytes(**argv, &param, CTX_ACTION_DATA);
        if (error_code != NO_ERROR) {
            psabpf_action_param_free(&param);
            fprintf(stderr, "Unable to parse action parameter: %s\n", **argv);
            return error_code;
        }
        error_code = psabpf_action_param(action, &param);
        if (error_code != NO_ERROR)
            return error_code;
    } while ((*argc) > 1);
    NEXT_ARGP();

    return NO_ERROR;
}

static int parse_member_reference(int *argc, char ***argv,
                                  psabpf_action_selector_member_context_t *member, bool is_last)
{
    char *ptr;
    psabpf_action_selector_set_member_reference(member, strtoul(**argv, &ptr, 0));
    if (*ptr) {
        fprintf(stderr, "%s: unable to parse as a member reference\n", **argv);
        return EINVAL;
    }

    if (is_last) {
        NEXT_ARGP();
    } else {
        NEXT_ARGP_RET();
    }

    return NO_ERROR;
}

static int parse_group_reference(int *argc, char ***argv, psabpf_action_selector_group_context_t *group)
{
    char *ptr;
    psabpf_action_selector_set_group_reference(group, strtoul(**argv, &ptr, 0));
    if (*ptr) {
        fprintf(stderr, "%s: unable to parse as a member reference\n", **argv);
        return EINVAL;
    }

    /* Always last parameter */
    NEXT_ARGP();

    return NO_ERROR;
}

static int parse_skip_keyword(int *argc, char ***argv, const char *keyword)
{
    if (!is_keyword(**argv, keyword)) {
        fprintf(stderr, "expected keyword \'%s\', got: %s\n", keyword, **argv);
        return EINVAL;
    }
    NEXT_ARGP_RET();
    return NO_ERROR;
}

typedef enum get_mode {
    GET_MODE_ALL,
    GET_MODE_MEMBER,
    GET_MODE_GROUP,
    GET_MODE_EMPTY_GROUP_ACTION
} get_mode_t;

static int parse_get_options(int *argc, char ***argv, get_mode_t *mode, uint32_t *reference)
{
    *mode = GET_MODE_ALL;

    if (*argc < 1)
        return NO_ERROR;

    if (is_keyword(**argv, "member") || is_keyword(**argv, "group")) {
        *mode = GET_MODE_MEMBER;
        if (is_keyword(**argv, "group"))
            *mode = GET_MODE_GROUP;
        NEXT_ARGP_RET();

        char *ptr;
        *reference = strtoul(**argv, &ptr, 0);
        if (*ptr) {
            fprintf(stderr, "%s: unable to parse as a member reference\n", **argv);
            return EINVAL;
        }
        NEXT_ARGP();
    } else if (is_keyword(**argv, "default_group_action")) {
        *mode = GET_MODE_EMPTY_GROUP_ACTION;
        NEXT_ARGP();
    }

    return NO_ERROR;
}

/******************************************************************************
 * JSON functions
 *****************************************************************************/

static int set_json_object_at_index(json_t *parent, json_t *object, uint32_t index)
{
    char idx_str[16]; /* index is 32 bits, 2^32=4.3e+9, so at least 11 bytes are required to convert idx to string */
    snprintf(idx_str, sizeof(idx_str), "%u", index);
    if (json_object_set_new(parent, idx_str, object) != 0)
        return EINVAL;

    return NO_ERROR;
}

json_t *create_json_member_entry_parameters(psabpf_action_selector_context_t *ctx, psabpf_action_selector_member_context_t *member)
{
    json_t *params_root = json_array();
    if (params_root == NULL)
        return NULL;

    psabpf_action_param_t *ap = NULL;
    while ((ap = psabpf_action_selector_action_param_get_next(member)) != NULL) {
        json_t *param_entry = json_object();
        if (param_entry == NULL) {
            json_decref(params_root);
            return NULL;
        }
        char *data = convert_bin_data_to_hexstr(psabpf_action_param_get_data(ap),
                                                psabpf_action_param_get_data_len(ap));
        if (data == NULL) {
            json_decref(params_root);
            json_decref(param_entry);
            return NULL;
        }
        const char *name = psabpf_action_selector_action_param_get_name(ctx, member, ap);

        if (name != NULL)
            json_object_set_new(param_entry, "name", json_string(name));
        json_object_set_new(param_entry, "value", json_string(data));
        json_array_append(params_root, param_entry);

        free(data);
        psabpf_action_param_free(ap);
    }

    return params_root;
}

json_t *create_json_member_entry(psabpf_action_selector_context_t *ctx, psabpf_action_selector_member_context_t *member)
{
    json_t *member_root = json_object();
    if (member_root == NULL)
        return NULL;

    json_object_set_new(member_root, "action_id", json_integer(psabpf_action_selector_get_member_action_id(ctx, member)));
    const char *action_name = psabpf_action_selector_get_member_action_name(ctx, member);
    if (action_name != NULL)
        json_object_set_new(member_root, "action_name", json_string(action_name));

    json_t *params = create_json_member_entry_parameters(ctx, member);
    if (params == NULL) {
        json_decref(member_root);
        return NULL;
    }
    json_object_set_new(member_root, "action_parameters", params);

    return member_root;
}

json_t *create_json_all_members(psabpf_action_selector_context_t *ctx)
{
    json_t *members_root = json_object();
    if (members_root == NULL)
        return NULL;

    psabpf_action_selector_member_context_t *member;
    while ((member = psabpf_action_selector_get_next_member(ctx)) != NULL) {
        json_t *member_json = create_json_member_entry(ctx, member);
        psabpf_action_selector_member_free(member);
        if (member_json == NULL) {
            json_decref(members_root);
            return NULL;
        }
        set_json_object_at_index(members_root, member_json, psabpf_action_selector_get_member_reference(member));
    }

    return members_root;
}

json_t *create_json_group_entry(psabpf_action_selector_context_t *ctx, psabpf_action_selector_group_context_t *group, json_t *member_refs)
{
    json_t *group_root = json_object();
    json_t *members = json_array();
    if (group_root ==NULL || members == NULL) {
        json_decref(group_root);
        json_decref(members);
        return NULL;
    }

    psabpf_action_selector_member_context_t *current_member;
    while ((current_member = psabpf_action_selector_get_next_group_member(ctx, group)) != NULL) {
        json_array_append_new(members, json_integer(psabpf_action_selector_get_member_reference(current_member)));
        if (member_refs != NULL) {
            set_json_object_at_index(member_refs,
                                     create_json_member_entry(ctx, current_member),
                                     psabpf_action_selector_get_member_reference(current_member));
        }
        psabpf_action_selector_member_free(current_member);
    }

    json_object_set_new(group_root, "member_refs", members);

    return group_root;
}

json_t *create_json_all_groups(psabpf_action_selector_context_t *ctx)
{
    json_t *groups_root = json_object();
    if (groups_root == NULL)
        return NULL;

    psabpf_action_selector_group_context_t *group;
    while ((group = psabpf_action_selector_get_next_group(ctx)) != NULL) {
        json_t *group_entry = create_json_group_entry(ctx, group, NULL);
        psabpf_action_selector_group_free(group);
        if (group_entry == NULL) {
            json_decref(groups_root);
            return NULL;
        }
        set_json_object_at_index(groups_root, group_entry, psabpf_action_selector_get_group_reference(group));
    }

    return groups_root;
}

json_t *create_json_empty_group_action(psabpf_action_selector_context_t *ctx)
{
    psabpf_action_selector_member_context_t ega;
    psabpf_action_selector_member_init(&ega);

    if (psabpf_action_selector_get_empty_group_action(ctx, &ega) != NO_ERROR) {
        fprintf(stderr, "failed to get empty group action\n");
        psabpf_action_selector_member_free(&ega);
        return NULL;
    }

    json_t *ega_root = create_json_member_entry(ctx, &ega);

    psabpf_action_selector_member_free(&ega);

    return ega_root;
}

int print_action_selector(psabpf_action_selector_context_t *ctx, const char *instance_name, get_mode_t mode, uint32_t reference)
{
    int ret = EINVAL;
    json_t *root = json_object();
    json_t *instance = json_object();
    json_t *members = NULL;
    json_t *groups = NULL;
    json_t *empty_group_action = NULL;

    bool failed = false;
    if (mode == GET_MODE_ALL) {
        members = create_json_all_members(ctx);
        groups = create_json_all_groups(ctx);
        empty_group_action = create_json_empty_group_action(ctx);

        if (members == NULL || groups == NULL || empty_group_action == NULL)
            failed = true;
    } else if (mode == GET_MODE_MEMBER) {
        members = json_object();
        psabpf_action_selector_member_context_t member;
        psabpf_action_selector_member_init(&member);
        psabpf_action_selector_set_member_reference(&member, reference);
        ret = psabpf_action_selector_get_member(ctx, &member);
        json_t *req_member = create_json_member_entry(ctx, &member);
        psabpf_action_selector_member_free(&member);

        if (members == NULL || ret != NO_ERROR || req_member == NULL) {
            json_decref(req_member);
            failed = true;
        } else {
            set_json_object_at_index(members, req_member, reference);
        }
    } else if (mode == GET_MODE_GROUP) {
        members = json_object();
        psabpf_action_selector_group_context_t group;
        psabpf_action_selector_group_init(&group);
        psabpf_action_selector_set_group_reference(&group, reference);
        ret = psabpf_action_selector_get_group(ctx, &group);
        groups = json_object();
        json_t *req_group = create_json_group_entry(ctx, &group, members);
        psabpf_action_selector_group_free(&group);

        if (members == NULL || ret != NO_ERROR || groups == NULL || req_group == NULL) {
            json_decref(req_group);
            failed = true;
        } else {
            set_json_object_at_index(groups, req_group, reference);
        }

    } else if (mode == GET_MODE_EMPTY_GROUP_ACTION) {
        empty_group_action = create_json_empty_group_action(ctx);

        if (empty_group_action == NULL)
            failed = true;
    }

    if (root == NULL || instance == NULL || failed) {
        fprintf(stderr, "failed to create JSON\n");
        ret = ENOMEM;
        goto clean_up;
    }

    if (json_object_set(root, instance_name, instance)) {
        fprintf(stderr, "failed to add JSON key %s\n", instance_name);
        goto clean_up;
    }

    if (members != NULL)
        json_object_set(instance, "member_refs", members);
    if (groups != NULL)
        json_object_set(instance, "group_refs", groups);
    if (empty_group_action != NULL)
        json_object_set(instance, "empty_group_action", empty_group_action);

    json_dumpf(root, stdout, JSON_INDENT(4) | JSON_ENSURE_ASCII);
    ret = NO_ERROR;

clean_up:
    json_decref(root);
    json_decref(instance);
    json_decref(members);
    json_decref(groups);
    json_decref(empty_group_action);

    return ret;
}

/******************************************************************************
 * Command line Action Selector functions
 *****************************************************************************/

int do_action_selector_add_member(int argc, char **argv)
{
    int error_code = EPERM;
    psabpf_context_t psabpf_ctx;
    psabpf_action_selector_context_t ctx;
    psabpf_action_t action;
    psabpf_action_selector_member_context_t member;

    psabpf_context_init(&psabpf_ctx);
    psabpf_action_selector_ctx_init(&ctx);
    psabpf_action_init(&action);
    psabpf_action_selector_member_init(&member);

    /* 0. Get the pipeline id */
    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR)
        goto clean_up;

    if (argc < 1) {
        fprintf(stderr, "too few parameters\n");
        goto clean_up;
    }

    /* 1. Get Action Selector */
    if (parse_dst_action_selector(&argc, &argv, &psabpf_ctx, &ctx, false, NULL) != NO_ERROR)
        goto clean_up;

    /* 2. Get action */
    if (parse_action_selector_action(&argc, &argv, &ctx, &action) != NO_ERROR)
        goto clean_up;

    /* 3. Get action parameters */
    if (parse_action_data(&argc, &argv, &action) != NO_ERROR)
        goto clean_up;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    psabpf_action_selector_member_action(&member, &action);

    error_code = psabpf_action_selector_add_member(&ctx, &member);
    if (error_code == NO_ERROR)
        fprintf(stdout, "%u\n", psabpf_action_selector_get_member_reference(&member));

clean_up:
    psabpf_action_selector_member_free(&member);
    psabpf_action_free(&action);
    psabpf_action_selector_ctx_free(&ctx);
    psabpf_context_free(&psabpf_ctx);

    return error_code;
}

int do_action_selector_delete_member(int argc, char **argv)
{
    int error_code = EPERM;
    psabpf_context_t psabpf_ctx;
    psabpf_action_selector_context_t ctx;
    psabpf_action_selector_member_context_t member;

    psabpf_context_init(&psabpf_ctx);
    psabpf_action_selector_ctx_init(&ctx);
    psabpf_action_selector_member_init(&member);

    /* 0. Get the pipeline id */
    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR)
        goto clean_up;

    if (argc < 1) {
        fprintf(stderr, "too few parameters\n");
        goto clean_up;
    }

    /* 1. Get Action Selector */
    if (parse_dst_action_selector(&argc, &argv, &psabpf_ctx, &ctx, false, NULL) != NO_ERROR)
        goto clean_up;

    /* 2. Get member reference */
    if (parse_member_reference(&argc, &argv, &member, true) != NO_ERROR)
        goto clean_up;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    error_code = psabpf_action_selector_del_member(&ctx, &member);

clean_up:
    psabpf_action_selector_member_free(&member);
    psabpf_action_selector_ctx_free(&ctx);
    psabpf_context_free(&psabpf_ctx);

    return error_code;
}

int do_action_selector_update_member(int argc, char **argv)
{
    int error_code = EPERM;
    psabpf_context_t psabpf_ctx;
    psabpf_action_selector_context_t ctx;
    psabpf_action_t action;
    psabpf_action_selector_member_context_t member;

    psabpf_context_init(&psabpf_ctx);
    psabpf_action_selector_ctx_init(&ctx);
    psabpf_action_init(&action);
    psabpf_action_selector_member_init(&member);

    /* 0. Get the pipeline id */
    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR)
        goto clean_up;

    if (argc < 1) {
        fprintf(stderr, "too few parameters\n");
        goto clean_up;
    }

    /* 1. Get Action Selector */
    if (parse_dst_action_selector(&argc, &argv, &psabpf_ctx, &ctx, false, NULL) != NO_ERROR)
        goto clean_up;

    /* 2. Get member reference */
    if (parse_member_reference(&argc, &argv, &member, false) != NO_ERROR)
        goto clean_up;

    /* 3. Get action */
    if (parse_action_selector_action(&argc, &argv, &ctx, &action) != NO_ERROR)
        goto clean_up;

    /* 4. Get action parameters */
    if (parse_action_data(&argc, &argv, &action) != NO_ERROR)
        goto clean_up;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    psabpf_action_selector_member_action(&member, &action);

    error_code = psabpf_action_selector_update_member(&ctx, &member);

clean_up:
    psabpf_action_selector_member_free(&member);
    psabpf_action_free(&action);
    psabpf_action_selector_ctx_free(&ctx);
    psabpf_context_free(&psabpf_ctx);

    return error_code;
}

int do_action_selector_create_group(int argc, char **argv)
{
    int error_code = EPERM;
    psabpf_context_t psabpf_ctx;
    psabpf_action_selector_context_t ctx;
    psabpf_action_selector_group_context_t group;

    psabpf_context_init(&psabpf_ctx);
    psabpf_action_selector_ctx_init(&ctx);
    psabpf_action_selector_group_init(&group);

    /* 0. Get the pipeline id */
    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR)
        goto clean_up;

    if (argc < 1) {
        fprintf(stderr, "too few parameters\n");
        goto clean_up;
    }

    /* 1. Get Action Selector */
    if (parse_dst_action_selector(&argc, &argv, &psabpf_ctx, &ctx, true, NULL) != NO_ERROR)
        goto clean_up;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    error_code = psabpf_action_selector_add_group(&ctx, &group);
    if (error_code == NO_ERROR)
        fprintf(stdout, "%u\n", psabpf_action_selector_get_group_reference(&group));

clean_up:
    psabpf_action_selector_group_free(&group);
    psabpf_action_selector_ctx_free(&ctx);
    psabpf_context_free(&psabpf_ctx);

    return error_code;
}

int do_action_selector_delete_group(int argc, char **argv)
{
    int error_code = EPERM;
    psabpf_context_t psabpf_ctx;
    psabpf_action_selector_context_t ctx;
    psabpf_action_selector_group_context_t group;

    psabpf_context_init(&psabpf_ctx);
    psabpf_action_selector_ctx_init(&ctx);
    psabpf_action_selector_group_init(&group);

    /* 0. Get the pipeline id */
    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR)
        goto clean_up;

    if (argc < 1) {
        fprintf(stderr, "too few parameters\n");
        goto clean_up;
    }

    /* 1. Get Action Selector */
    if (parse_dst_action_selector(&argc, &argv, &psabpf_ctx, &ctx, false, NULL) != NO_ERROR)
        goto clean_up;

    /* 2. Get group reference */
    if (parse_group_reference(&argc, &argv, &group) != NO_ERROR)
        goto clean_up;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    error_code = psabpf_action_selector_del_group(&ctx, &group);

clean_up:
    psabpf_action_selector_group_free(&group);
    psabpf_action_selector_ctx_free(&ctx);
    psabpf_context_free(&psabpf_ctx);

    return error_code;
}

static int add_or_remove_member_from_group(int argc, char **argv, bool add)
{
    int error_code = EPERM;
    psabpf_context_t psabpf_ctx;
    psabpf_action_selector_context_t ctx;
    psabpf_action_selector_member_context_t member;
    psabpf_action_selector_group_context_t group;

    psabpf_context_init(&psabpf_ctx);
    psabpf_action_selector_ctx_init(&ctx);
    psabpf_action_selector_member_init(&member);
    psabpf_action_selector_group_init(&group);

    /* 0. Get the pipeline id */
    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR)
        goto clean_up;

    if (argc < 1) {
        fprintf(stderr, "too few parameters\n");
        goto clean_up;
    }

    /* 1. Get Action Selector */
    if (parse_dst_action_selector(&argc, &argv, &psabpf_ctx, &ctx, false, NULL) != NO_ERROR)
        goto clean_up;

    /* 2. Get member reference */
    if (parse_member_reference(&argc, &argv, &member, false) != NO_ERROR)
        goto clean_up;

    /* 3. Skip keyword */
    if (add) {
        if (parse_skip_keyword(&argc, &argv, "to") != NO_ERROR)
            goto clean_up;
    } else {
        if (parse_skip_keyword(&argc, &argv, "from") != NO_ERROR)
            goto clean_up;
    }

    /* 4. Get group reference */
    if (parse_group_reference(&argc, &argv, &group) != NO_ERROR)
        goto clean_up;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    if (add)
        error_code = psabpf_action_selector_add_member_to_group(&ctx, &group, &member);
    else
        error_code = psabpf_action_selector_del_member_from_group(&ctx, &group, &member);

clean_up:
    psabpf_action_selector_group_free(&group);
    psabpf_action_selector_member_free(&member);
    psabpf_action_selector_ctx_free(&ctx);
    psabpf_context_free(&psabpf_ctx);

    return error_code;
}

int do_action_selector_add_to_group(int argc, char **argv)
{
    return add_or_remove_member_from_group(argc, argv, true);
}

int do_action_selector_delete_from_group(int argc, char **argv)
{
    return add_or_remove_member_from_group(argc, argv, false);
}

int do_action_selector_default_group_action(int argc, char **argv)
{
    int error_code = EPERM;
    psabpf_context_t psabpf_ctx;
    psabpf_action_selector_context_t ctx;
    psabpf_action_t action;

    psabpf_context_init(&psabpf_ctx);
    psabpf_action_selector_ctx_init(&ctx);
    psabpf_action_init(&action);

    /* 0. Get the pipeline id */
    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR)
        goto clean_up;

    if (argc < 1) {
        fprintf(stderr, "too few parameters\n");
        goto clean_up;
    }

    /* 1. Get Action Selector */
    if (parse_dst_action_selector(&argc, &argv, &psabpf_ctx, &ctx, false, NULL) != NO_ERROR)
        goto clean_up;

    /* 2. Get action */
    if (parse_action_selector_action(&argc, &argv, &ctx, &action) != NO_ERROR)
        goto clean_up;

    /* 3. Get action parameters */
    if (parse_action_data(&argc, &argv, &action) != NO_ERROR)
        goto clean_up;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    error_code = psabpf_action_selector_set_empty_group_action(&ctx, &action);

clean_up:
    psabpf_action_free(&action);
    psabpf_action_selector_ctx_free(&ctx);
    psabpf_context_free(&psabpf_ctx);

    return error_code;
}

int do_action_selector_get(int argc, char **argv)
{
    int error_code = EPERM;
    const char *instance_name;
    psabpf_context_t psabpf_ctx;
    psabpf_action_selector_context_t ctx;

    psabpf_context_init(&psabpf_ctx);
    psabpf_action_selector_ctx_init(&ctx);

    /* 0. Get the pipeline id */
    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR)
        goto clean_up;

    if (argc < 1) {
        fprintf(stderr, "too few parameters\n");
        goto clean_up;
    }

    /* 1. Get Action Selector */
    if (parse_dst_action_selector(&argc, &argv, &psabpf_ctx, &ctx, true, &instance_name) != NO_ERROR)
        goto clean_up;

    /* 2. Try to get specific mode */
    get_mode_t mode;
    uint32_t reference = 0;
    if (parse_get_options(&argc, &argv, &mode, &reference) != NO_ERROR)
        goto clean_up;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    error_code = print_action_selector(&ctx, instance_name, mode, reference);

clean_up:
    psabpf_action_selector_ctx_free(&ctx);
    psabpf_context_free(&psabpf_ctx);

    return error_code;
}

int do_action_selector_help(int argc, char **argv)
{
    (void) argc; (void) argv;

    fprintf(stderr,
            "Usage: %1$s action-selector add_member pipe ID ACTION_SELECTOR_NAME action ACTION [data ACTION_PARAMS]\n"
            "       %1$s action-selector delete_member pipe ID ACTION_SELECTOR_NAME MEMBER_REF\n"
            "       %1$s action-selector update_member pipe ID ACTION_SELECTOR_NAME MEMBER_REF action ACTION [data ACTION_PARAMS]\n"
            ""
            "       %1$s action-selector create_group pipe ID ACTION_SELECTOR_NAME\n"
            "       %1$s action-selector delete_group pipe ID ACTION_SELECTOR_NAME GROUP_REF\n"
            ""
            "       %1$s action-selector add_to_group pipe ID ACTION_SELECTOR_NAME MEMBER_REF to GROUP_REF\n"
            "       %1$s action-selector delete_from_group pipe ID ACTION_SELECTOR_NAME MEMBER_REF from GROUP_REF\n"
            ""
            /* TODO: rename to empty group action, not default */
            "       %1$s action-selector default_group_action pipe ID ACTION_SELECTOR_NAME action ACTION [data ACTION_PARAMS]\n"
            ""
            "       %1$s action-selector get pipe ID ACTION_SELECTOR_NAME [member MEMBER_REF | group GROUP_REF | default_group_action]"
            "\n"
            "       ACTION := { id ACTION_ID | name ACTION_NAME }\n"
            "       ACTION_PARAMS := { DATA }\n"
            "",
            program_name);
    return 0;
}
