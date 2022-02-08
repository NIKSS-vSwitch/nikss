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

#include "multicast.h"
#include <psabpf_pre.h>

int do_multicast_create_group(int argc, char **argv)
{
    psabpf_context_t ctx;
    psabpf_mcast_grp_ctx_t mcast_grp;
    int ret = EINVAL;

    psabpf_context_init(&ctx);
    psabpf_mcast_grp_context_init(&mcast_grp);

    if (parse_pipeline_id(&argc, &argv, &ctx) != NO_ERROR)
        goto err;

    psabpf_mcast_grp_id_t group_id;
    parser_keyword_value_pair_t kv[] = {
            {"id", &group_id, sizeof(group_id), true, "multicast group id"},
            { 0 },
    };

    if (parse_keyword_value_pairs(&argc, &argv, &kv[0]) != NO_ERROR)
        goto err;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto err;
    }

    psabpf_mcast_grp_id(&mcast_grp, group_id);

    if (psabpf_mcast_grp_exists(&ctx, &mcast_grp)) {
        fprintf(stderr, "multicast group %u already exists\n", group_id);
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

    if (parse_pipeline_id(&argc, &argv, &ctx) != NO_ERROR)
        goto err;

    psabpf_mcast_grp_id_t group_id;
    parser_keyword_value_pair_t kv[] = {
            {"id", &group_id, sizeof(group_id), true, "multicast group id"},
            { 0 },
    };

    if (parse_keyword_value_pairs(&argc, &argv, &kv[0]) != NO_ERROR)
        goto err;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto err;
    }

    psabpf_mcast_grp_id(&mcast_grp, group_id);

    if (!psabpf_mcast_grp_exists(&ctx, &mcast_grp)) {
        fprintf(stderr, "multicast group %u does not exist\n", group_id);
        ret = ENOENT;
        goto err;
    }

    ret = psabpf_mcast_grp_delete(&ctx, &mcast_grp);

err:
    psabpf_mcast_grp_context_free(&mcast_grp);
    psabpf_context_free(&ctx);

    return ret;
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

    if (parse_pipeline_id(&argc, &argv, &ctx) != NO_ERROR)
        goto err;

    psabpf_mcast_grp_id_t group_id;
    uint32_t egress_port;
    uint16_t instance;
    parser_keyword_value_pair_t kv[] = {
            {"id",          &group_id,    sizeof(group_id),    true, "multicast group id"},
            {"egress-port", &egress_port, sizeof(egress_port), true, "egress port"},
            {"instance",    &instance,    sizeof(instance),    true, "egress port instance"},
            { 0 },
    };

    if (parse_keyword_value_pairs(&argc, &argv, &kv[0]) != NO_ERROR)
        goto err;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto err;
    }

    psabpf_mcast_grp_id(&mcast_grp, group_id);
    psabpf_mcast_grp_member_port(&member, egress_port);
    psabpf_mcast_grp_member_instance(&member, instance);

    if (!psabpf_mcast_grp_exists(&ctx, &mcast_grp)) {
        fprintf(stderr, "multicast group %u does not exist\n", group_id);
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

    if (parse_pipeline_id(&argc, &argv, &ctx) != NO_ERROR)
        goto err;

    psabpf_mcast_grp_id_t group_id;
    uint32_t egress_port;
    uint16_t instance;
    parser_keyword_value_pair_t kv[] = {
            {"id",          &group_id,    sizeof(group_id),    true, "multicast group id"},
            {"egress-port", &egress_port, sizeof(egress_port), true, "egress port"},
            {"instance",    &instance,    sizeof(instance),    true, "egress port instance"},
            { 0 },
    };

    if (parse_keyword_value_pairs(&argc, &argv, &kv[0]) != NO_ERROR)
        goto err;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto err;
    }

    psabpf_mcast_grp_id(&mcast_grp, group_id);
    psabpf_mcast_grp_member_port(&member, egress_port);
    psabpf_mcast_grp_member_instance(&member, instance);

    if (!psabpf_mcast_grp_exists(&ctx, &mcast_grp)) {
        fprintf(stderr, "multicast group %u does not exist\n", group_id);
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

int do_multicast_help(int argc, char **argv)
{
    (void) argc; (void) argv;
    fprintf(stderr,
        "Usage: %1$s multicast-group create pipe ID MULTICAST_GROUP\n"
        "       %1$s multicast-group delete pipe ID MULTICAST_GROUP\n"
        "       %1$s multicast-group add-member pipe ID MULTICAST_GROUP egress-port OUTPUT_PORT instance INSTANCE_ID\n"
        "       %1$s multicast-group del-member pipe ID MULTICAST_GROUP egress-port OUTPUT_PORT instance INSTANCE_ID\n"
        "\n"
        "       MULTICAST_GROUP := id MULTICAST_GROUP_ID\n"
        "",
        program_name);

    return 0;
}
