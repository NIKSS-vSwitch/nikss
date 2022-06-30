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
#include <errno.h>
#include <jansson.h>

#include "multicast.h"
#include <psabpf_pre.h>

static int parse_group(int *argc, char ***argv, psabpf_context_t *ctx, psabpf_mcast_grp_ctx_t *mcast_grp)
{
    int ret = parse_pipeline_id(argc, argv, ctx);
    if (ret != NO_ERROR)
        return ret;

    psabpf_mcast_grp_id_t group_id;
    parser_keyword_value_pair_t kv[] = {
            {"id", &group_id, sizeof(group_id), true, "multicast group id"},
            { 0 },
    };

    ret = parse_keyword_value_pairs(argc, argv, &kv[0]);
    if (ret != NO_ERROR)
        return ret;

    psabpf_mcast_grp_id(mcast_grp, group_id);

    return NO_ERROR;
}

int do_multicast_create_group(int argc, char **argv)
{
    psabpf_context_t ctx;
    psabpf_mcast_grp_ctx_t mcast_grp;
    int ret = EINVAL;

    psabpf_context_init(&ctx);
    psabpf_mcast_grp_context_init(&mcast_grp);

    if (parse_group(&argc, &argv, &ctx, &mcast_grp) != NO_ERROR)
        goto err;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto err;
    }

    if (psabpf_mcast_grp_exists(&ctx, &mcast_grp)) {
        fprintf(stderr, "multicast group already exists\n");
        ret = EEXIST;
        goto err;
    }

    ret = psabpf_mcast_grp_create(&ctx, &mcast_grp);

err:
    psabpf_mcast_grp_context_free(&mcast_grp);
    psabpf_context_free(&ctx);

    return ret;
}

int do_multicast_delete_group(int argc, char **argv)
{
    psabpf_context_t ctx;
    psabpf_mcast_grp_ctx_t mcast_grp;
    int ret = EINVAL;

    psabpf_context_init(&ctx);
    psabpf_mcast_grp_context_init(&mcast_grp);

    if (parse_group(&argc, &argv, &ctx, &mcast_grp) != NO_ERROR)
        goto err;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto err;
    }

    if (!psabpf_mcast_grp_exists(&ctx, &mcast_grp)) {
        fprintf(stderr, "multicast group does not exist\n");
        ret = ENOENT;
        goto err;
    }

    ret = psabpf_mcast_grp_delete(&ctx, &mcast_grp);

err:
    psabpf_mcast_grp_context_free(&mcast_grp);
    psabpf_context_free(&ctx);

    return ret;
}

static int parse_group_and_member(int *argc, char ***argv, psabpf_context_t *ctx,
                                  psabpf_mcast_grp_ctx_t *mcast_grp, psabpf_mcast_grp_member_t *member)
{
    int ret = parse_group(argc, argv, ctx, mcast_grp);
    if (ret != NO_ERROR)
        return ret;

    uint32_t egress_port;
    uint16_t instance;
    parser_keyword_value_pair_t kv[] = {
            {"egress-port", &egress_port, sizeof(egress_port), true, "egress port"},
            {"instance",    &instance,    sizeof(instance),    true, "egress port instance"},
            { 0 },
    };

    ret = parse_keyword_value_pairs(argc, argv, &kv[0]);
    if (ret != NO_ERROR)
        return ret;

    psabpf_mcast_grp_member_port(member, egress_port);
    psabpf_mcast_grp_member_instance(member, instance);

    return NO_ERROR;
}

int do_multicast_add_group_member(int argc, char **argv)
{
    psabpf_context_t ctx;
    psabpf_mcast_grp_ctx_t mcast_grp;
    psabpf_mcast_grp_member_t member;
    int ret = EINVAL;

    psabpf_context_init(&ctx);
    psabpf_mcast_grp_context_init(&mcast_grp);
    psabpf_mcast_grp_member_init(&member);

    if (parse_group_and_member(&argc, &argv, &ctx, &mcast_grp, &member) != NO_ERROR)
        goto err;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto err;
    }

    if (!psabpf_mcast_grp_exists(&ctx, &mcast_grp)) {
        fprintf(stderr, "multicast group does not exist\n");
        ret = ENOENT;
        goto err;
    }

    ret = psabpf_mcast_grp_member_update(&ctx, &mcast_grp, &member);

err:
    psabpf_mcast_grp_member_free(&member);
    psabpf_mcast_grp_context_free(&mcast_grp);
    psabpf_context_free(&ctx);

    return ret;
}

int do_multicast_del_group_member(int argc, char **argv)
{
    psabpf_context_t ctx;
    psabpf_mcast_grp_ctx_t mcast_grp;
    psabpf_mcast_grp_member_t member;
    int ret = EINVAL;

    psabpf_context_init(&ctx);
    psabpf_mcast_grp_context_init(&mcast_grp);
    psabpf_mcast_grp_member_init(&member);

    if (parse_group_and_member(&argc, &argv, &ctx, &mcast_grp, &member) != NO_ERROR)
        goto err;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto err;
    }

    if (!psabpf_mcast_grp_exists(&ctx, &mcast_grp)) {
        fprintf(stderr, "multicast group does not exist\n");
        ret = ENOENT;
        goto err;
    }

    ret = psabpf_mcast_grp_member_delete(&ctx, &mcast_grp, &member);

err:
    psabpf_mcast_grp_member_free(&member);
    psabpf_mcast_grp_context_free(&mcast_grp);
    psabpf_context_free(&ctx);

    return ret;
}

static json_t *create_json_single_group(psabpf_context_t *ctx, psabpf_mcast_grp_ctx_t *group)
{
    json_t *root = json_array();
    if (root == NULL)
        return NULL;

    psabpf_mcast_grp_member_t *member;
    while ((member = psabpf_mcast_grp_get_next_member(ctx, group)) != NULL) {
        json_t *member_root = json_object();
        if (member_root == NULL) {
            json_decref(root);
            return NULL;
        }

        json_object_set_new(member_root, "port", json_integer(psabpf_mcast_grp_member_get_port(member)));
        json_object_set_new(member_root, "instance", json_integer(psabpf_mcast_grp_member_get_instance(member)));
        json_array_append_new(root, member_root);

        psabpf_mcast_grp_member_free(member);
    }

    return root;
}

static int print_single_mcast_group(psabpf_context_t *ctx, psabpf_mcast_grp_ctx_t *group)
{
    json_t *root = json_object();
    json_t *groups = json_object();
    json_t *group_json = create_json_single_group(ctx, group);

    if (root == NULL || groups == NULL || group_json == NULL)
        goto clean_up;

    json_object_set(root, "multicast-groups", groups);
    set_json_object_at_index(groups, group_json, psabpf_mcast_grp_get_id(group));

    json_dumpf(root, stdout, JSON_INDENT(4) | JSON_ENSURE_ASCII);

clean_up:
    json_decref(root);
    json_decref(groups);
    json_decref(group_json);

    return NO_ERROR;
}

int do_multicast_get(int argc, char **argv)
{
    psabpf_context_t ctx;
    psabpf_mcast_grp_ctx_t group;
    psabpf_mcast_grp_member_t *member;

    psabpf_context_init(&ctx);
    psabpf_context_set_pipeline(&ctx, 1);
    psabpf_mcast_grp_context_init(&group);
    psabpf_mcast_grp_id(&group, 8);

    print_single_mcast_group(&ctx, &group);

    psabpf_mcast_grp_context_free(&group);
    psabpf_context_free(&ctx);

    return NO_ERROR;
}

int do_multicast_help(int argc, char **argv)
{
    (void) argc; (void) argv;
    fprintf(stderr,
        "Usage: %1$s multicast-group create pipe ID MULTICAST_GROUP\n"
        "       %1$s multicast-group delete pipe ID MULTICAST_GROUP\n"
        "       %1$s multicast-group add-member pipe ID MULTICAST_GROUP egress-port OUTPUT_PORT instance INSTANCE_ID\n"
        "       %1$s multicast-group del-member pipe ID MULTICAST_GROUP egress-port OUTPUT_PORT instance INSTANCE_ID\n"
        "       %1$s multicast-group get pipe ID [MULTICAST_GROUP]\n"
        "\n"
        "       MULTICAST_GROUP := id MULTICAST_GROUP_ID\n"
        "",
        program_name);

    return 0;
}
