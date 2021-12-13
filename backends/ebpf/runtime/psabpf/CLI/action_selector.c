#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "common.h"
#include "action_selector.h"

/******************************************************************************
 * Command line parsing functions
 *****************************************************************************/

static int parse_dst_action_selector(int *argc, char ***argv, psabpf_context_t *psabpf_ctx,
                             psabpf_action_selector_context_t *ctx, bool is_last)
{
    if (is_keyword(**argv, "id")) {
        NEXT_ARGP_RET();
        fprintf(stderr, "id: Action Selector access not supported\n");
        return ENOTSUP;
    } else if (is_keyword(**argv, "name")) {
        NEXT_ARGP_RET();
        fprintf(stderr, "name: Action Selector access not supported yet\n");
        return ENOTSUP;
    } else {
        int error_code = psabpf_action_selector_ctx_open(psabpf_ctx, ctx, **argv);
        if (error_code != NO_ERROR)
            return error_code;
    }

    if (is_last) {
        NEXT_ARGP();
    } else {
        NEXT_ARGP_RET();
    }

    return NO_ERROR;
}

static int parse_action_selector_action(int *argc, char ***argv, psabpf_action_t *action)
{
    if (is_keyword(**argv, "id")) {
        NEXT_ARGP_RET();
        char *ptr;
        psabpf_action_set_id(action, strtoul(**argv, &ptr, 0));
        if (*ptr) {
            fprintf(stderr, "%s: unable to parse as an action id\n", **argv);
            return EINVAL;
        }
    } else {
        fprintf(stderr, "specify an action by name is not supported yet\n");
        return ENOTSUP;
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
    if (parse_dst_action_selector(&argc, &argv, &psabpf_ctx, &ctx, false) != NO_ERROR)
        goto clean_up;

    /* 2. Get action */
    if (parse_action_selector_action(&argc, &argv, &action) != NO_ERROR)
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
    if (parse_dst_action_selector(&argc, &argv, &psabpf_ctx, &ctx, false) != NO_ERROR)
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
    if (parse_dst_action_selector(&argc, &argv, &psabpf_ctx, &ctx, false) != NO_ERROR)
        goto clean_up;

    /* 2. Get member reference */
    if (parse_member_reference(&argc, &argv, &member, false) != NO_ERROR)
        goto clean_up;

    /* 3. Get action */
    if (parse_action_selector_action(&argc, &argv, &action) != NO_ERROR)
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
    if (parse_dst_action_selector(&argc, &argv, &psabpf_ctx, &ctx, true) != NO_ERROR)
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
    if (parse_dst_action_selector(&argc, &argv, &psabpf_ctx, &ctx, false) != NO_ERROR)
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
    if (parse_dst_action_selector(&argc, &argv, &psabpf_ctx, &ctx, false) != NO_ERROR)
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
    if (parse_dst_action_selector(&argc, &argv, &psabpf_ctx, &ctx, false) != NO_ERROR)
        goto clean_up;

    /* 2. Get action */
    if (parse_action_selector_action(&argc, &argv, &action) != NO_ERROR)
        goto clean_up;

    /* 3. Get action parameters */
    if (parse_action_data(&argc, &argv, &action) != NO_ERROR)
        goto clean_up;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    error_code = psabpf_action_selector_set_default_group_action(&ctx, &action);

clean_up:
    psabpf_action_free(&action);
    psabpf_action_selector_ctx_free(&ctx);
    psabpf_context_free(&psabpf_ctx);

    return error_code;
}

int do_action_selector_help(int argc, char **argv)
{
    (void) argc; (void) argv;

    fprintf(stderr,
            "Usage: %1$s action-selector add_member pipe ID ACTION_SELECTOR ACTION [data ACTION_PARAMS]\n"
            "       %1$s action-selector delete_member pipe ID ACTION_SELECTOR MEMBER_REF\n"
            "       %1$s action-selector update_member pipe ID ACTION_SELECTOR MEMBER_REF ACTION [data ACTION_PARAMS]\n"
            ""
            "       %1$s action-selector create_group pipe ID ACTION_SELECTOR\n"
            "       %1$s action-selector delete_group pipe ID ACTION_SELECTOR GROUP_REF\n"
            ""
            "       %1$s action-selector add_to_group pipe ID ACTION_SELECTOR MEMBER_REF to GROUP_REF\n"
            "       %1$s action-selector delete_from_group pipe ID ACTION_SELECTOR MEMBER_REF from GROUP_REF\n"
            ""
            "       %1$s action-selector default_group_action pipe ID ACTION_SELECTOR ACTION [data ACTION_PARAMS]\n"
            "\n"
            "       ACTION_SELECTOR := { id ACTION_SELECTOR_ID | name FILE | ACTION_SELECTOR_FILE }\n"
            "       ACTION := { id ACTION_ID | ACTION_NAME }\n"
            "       ACTION_PARAMS := { DATA }\n"
            "",
            program_name);
    return 0;
}
