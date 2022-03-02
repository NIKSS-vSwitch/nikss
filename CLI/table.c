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
#include <stdbool.h>
#include <string.h>

#include <errno.h>

#include "../include/psabpf.h"
#include "table.h"
#include "common.h"
#include "counter.h"

/******************************************************************************
 * Command line parsing functions
 *****************************************************************************/

static int parse_dst_table(int *argc, char ***argv, psabpf_context_t *psabpf_ctx,
                           psabpf_table_entry_ctx_t *ctx, bool can_be_last)
{
    if (is_keyword(**argv, "id")) {
        NEXT_ARGP_RET();
        fprintf(stderr, "id: table access not supported\n");
        return ENOTSUP;
    } else if (is_keyword(**argv, "name")) {
        NEXT_ARGP_RET();
        fprintf(stderr, "name: table access not supported yet\n");
        return ENOTSUP;
    } else {
        int error_code = psabpf_table_entry_ctx_tblname(psabpf_ctx, ctx, **argv);
        if (error_code != NO_ERROR)
            return error_code;
    }

    if (can_be_last) {
        NEXT_ARGP();
    } else {
        NEXT_ARGP_RET();
    }

    return NO_ERROR;
}

static int parse_table_action(int *argc, char ***argv, psabpf_table_entry_ctx_t *ctx,
                              psabpf_action_t *action, bool *indirect_table)
{
    *indirect_table = false;

    if (is_keyword(**argv, "id")) {
        NEXT_ARGP_RET();
        char *ptr;
        psabpf_action_set_id(action, strtoul(**argv, &ptr, 0));
        if (*ptr) {
            fprintf(stderr, "%s: unable to parse as an action id\n", **argv);
            return EINVAL;
        }
    } else if (is_keyword(**argv, "ref")) {
        *indirect_table = true;
        psabpf_table_entry_ctx_mark_indirect(ctx);
    } else {
        fprintf(stderr, "specify an action by name is not supported yet\n");
        return ENOTSUP;
    }
    NEXT_ARGP_RET();

    return NO_ERROR;
}

static int parse_table_key(int *argc, char ***argv, psabpf_table_entry_t *entry)
{
    bool has_any_key = false;
    int error_code = EPERM;

    if (!is_keyword(**argv, "key"))
        return NO_ERROR;

    do {
        NEXT_ARGP_RET();
        if (is_keyword(**argv, "data") || is_keyword(**argv, "priority"))
            return NO_ERROR;

        if (is_keyword(**argv, "none")) {
            if (!has_any_key) {
                NEXT_ARGP();
                return NO_ERROR;
            } else {
                fprintf(stderr, "Unexpected none key\n");
                return EPERM;
            }
        }

        psabpf_match_key_t mk;
        psabpf_matchkey_init(&mk);
        char *substr_ptr;
        if ((substr_ptr = strstr(**argv, "/")) != NULL) {
            psabpf_matchkey_type(&mk, PSABPF_LPM);
            *(substr_ptr++) = 0;
            if (*substr_ptr == 0) {
                fprintf(stderr, "missing prefix length for LPM key\n");
                return EINVAL;
            }
            error_code = translate_data_to_bytes(**argv, &mk, CTX_MATCH_KEY);
            if (error_code != NO_ERROR)
                return error_code;
            char *ptr;
            psabpf_matchkey_prefix(&mk, strtoul(substr_ptr, &ptr, 0));
            if (*ptr) {
                fprintf(stderr, "%s: unable to parse prefix length\n", substr_ptr);
                return EINVAL;
            }
        } else if (strstr(**argv, "..") != NULL) {
            fprintf(stderr, "range match key not supported yet\n");
            return ENOTSUP;
        } else if ((substr_ptr = strstr(**argv, "^")) != NULL) {
            psabpf_matchkey_type(&mk, PSABPF_TERNARY);
            /* Split data and mask */
            *substr_ptr = 0;
            substr_ptr++;
            if (*substr_ptr == 0) {
                fprintf(stderr, "missing mask for ternary key\n");
                return EINVAL;
            }
            error_code = translate_data_to_bytes(**argv, &mk, CTX_MATCH_KEY);
            if (error_code != NO_ERROR)
                return error_code;
            error_code = translate_data_to_bytes(substr_ptr, &mk, CTX_MATCH_KEY_TERNARY_MASK);
            if (error_code != NO_ERROR)
                return error_code;
        } else {
            psabpf_matchkey_type(&mk, PSABPF_EXACT);
            error_code = translate_data_to_bytes(**argv, &mk, CTX_MATCH_KEY);
            if (error_code != NO_ERROR)
                return error_code;
        }
        error_code = psabpf_table_entry_matchkey(entry, &mk);
        psabpf_matchkey_free(&mk);
        if (error_code != NO_ERROR)
            return error_code;

        has_any_key = true;
    } while ((*argc) > 1);
    NEXT_ARGP();

    return NO_ERROR;
}

static int parse_direct_counter_entry(int *argc, char ***argv,
                                      psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry,
                                      psabpf_direct_counter_context_t *dc, psabpf_counter_entry_t *counter)
{
    if (!is_keyword(**argv, "counter"))
        return EINVAL;

    NEXT_ARGP_RET();
    const char *instance = **argv;
    NEXT_ARGP_RET();

    int ret = psabpf_direct_counter_ctx_name(dc, ctx, instance);
    if (ret != NO_ERROR) {
        fprintf(stderr, "%s: DirectCounter not found\n", instance);
        return ret;
    }

    ret = parse_counter_value_str(**argv, psabpf_direct_counter_get_type(dc), counter);
    if (ret != NO_ERROR)
        return ret;

    ret = psabpf_table_entry_set_direct_counter(entry, dc, counter);
    if (ret != NO_ERROR)
        fprintf(stderr, "%s: failed to append DirectCounter to table entry\n", instance);

    return ret;
}

static int parse_action_data(int *argc, char ***argv, psabpf_table_entry_ctx_t *ctx,
                             psabpf_table_entry_t *entry, psabpf_action_t *action, bool indirect_table)
{
    if (!is_keyword(**argv, "data")) {
        if (indirect_table) {
            fprintf(stderr, "expected action reference\n");
            return EINVAL;
        }
        return NO_ERROR;
    }

    do {
        NEXT_ARGP_RET();
        if (is_keyword(**argv, "priority"))
            return NO_ERROR;

        bool ref_is_group_ref = false;
        if (indirect_table) {
            if (is_keyword(**argv, "group")) {
                ref_is_group_ref = true;
                NEXT_ARGP_RET();
            }
        } else {
            if (is_keyword(**argv, "counter")) {
                psabpf_direct_counter_context_t dc;
                psabpf_counter_entry_t counter;

                psabpf_direct_counter_ctx_init(&dc);
                psabpf_counter_entry_init(&counter);

                int ret = parse_direct_counter_entry(argc, argv, ctx, entry, &dc, &counter);
                psabpf_counter_entry_free(&counter);
                psabpf_direct_counter_ctx_free(&dc);
                if (ret != NO_ERROR)
                    return ret;

                continue;
            }
        }

        psabpf_action_param_t param;
        int error_code = translate_data_to_bytes(**argv, &param, CTX_ACTION_DATA);
        if (error_code != NO_ERROR) {
            psabpf_action_param_free(&param);
            return error_code;
        }
        if (ref_is_group_ref)
            psabpf_action_param_mark_group_reference(&param);
        error_code = psabpf_action_param(action, &param);
        if (error_code != NO_ERROR)
            return error_code;
    } while ((*argc) > 1);
    NEXT_ARGP();

    return NO_ERROR;
}

static int parse_entry_priority(int *argc, char ***argv, psabpf_table_entry_t *entry)
{
    if (!is_keyword(**argv, "priority"))
        return NO_ERROR;
    NEXT_ARGP_RET();

    char *ptr;
    psabpf_table_entry_priority(entry, strtoul(**argv, &ptr, 0));
    if (*ptr) {
        fprintf(stderr, "%s: unable to parse priority\n", **argv);
        return EINVAL;
    }
    NEXT_ARGP();

    return NO_ERROR;
}

/******************************************************************************
 * Command line table functions
 *****************************************************************************/

enum table_write_type_t {
    TABLE_ADD_NEW_ENTRY,
    TABLE_UPDATE_EXISTING_ENTRY
};

int do_table_write(int argc, char **argv, enum table_write_type_t write_type)
{
    psabpf_table_entry_t entry;
    psabpf_table_entry_ctx_t ctx;
    psabpf_action_t action;
    psabpf_context_t psabpf_ctx;
    int error_code = EPERM;
    bool table_is_indirect = false;

    psabpf_context_init(&psabpf_ctx);
    psabpf_table_entry_ctx_init(&ctx);
    psabpf_table_entry_init(&entry);
    psabpf_action_init(&action);

    /* 0. Get the pipeline id */
    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR)
        goto clean_up;

    /* no NEXT_ARG before in version from this file, so this check must be preserved */
    if (argc < 1) {
        fprintf(stderr, "too few parameters\n");
        goto clean_up;
    }

    /* 1. Get table */
    if (parse_dst_table(&argc, &argv, &psabpf_ctx, &ctx, false) != NO_ERROR)
        goto clean_up;

    /* 2. Get action */
    if (parse_table_action(&argc, &argv, &ctx, &action, &table_is_indirect) != NO_ERROR)
        goto clean_up;

    /* 3. Get key */
    if (parse_table_key(&argc, &argv, &entry) != NO_ERROR)
        goto clean_up;

    /* 4. Get action parameters */
    if (parse_action_data(&argc, &argv, &ctx, &entry, &action, table_is_indirect) != NO_ERROR)
        goto clean_up;

    /* 5. Get entry priority */
    if (parse_entry_priority(&argc, &argv, &entry) != NO_ERROR)
        goto clean_up;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    psabpf_table_entry_action(&entry, &action);

    if (write_type == TABLE_ADD_NEW_ENTRY)
        error_code = psabpf_table_entry_add(&ctx, &entry);
    else if (write_type == TABLE_UPDATE_EXISTING_ENTRY)
        error_code = psabpf_table_entry_update(&ctx, &entry);

clean_up:
    psabpf_action_free(&action);
    psabpf_table_entry_free(&entry);
    psabpf_table_entry_ctx_free(&ctx);
    psabpf_context_free(&psabpf_ctx);

    return error_code;
}

int do_table_add(int argc, char **argv)
{
    return do_table_write(argc, argv, TABLE_ADD_NEW_ENTRY);
}

int do_table_update(int argc, char **argv)
{
    return do_table_write(argc, argv, TABLE_UPDATE_EXISTING_ENTRY);
}

int do_table_delete(int argc, char **argv)
{
    psabpf_table_entry_t entry;
    psabpf_table_entry_ctx_t ctx;
    psabpf_context_t psabpf_ctx;
    int error_code = EPERM;

    psabpf_context_init(&psabpf_ctx);
    psabpf_table_entry_ctx_init(&ctx);
    psabpf_table_entry_init(&entry);

    /* 0. Get the pipeline id */
    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR)
        goto clean_up;

    /* no NEXT_ARG before in version from this file, so this check must be preserved */
    if (argc < 1) {
        fprintf(stderr, "too few parameters\n");
        goto clean_up;
    }

    /* 1. Get table */
    if (parse_dst_table(&argc, &argv, &psabpf_ctx, &ctx, true) != NO_ERROR)
        goto clean_up;

    /* 2. Get key */
    if (parse_table_key(&argc, &argv, &entry) != NO_ERROR)
        goto clean_up;

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    error_code = psabpf_table_entry_del(&ctx, &entry);

clean_up:
    psabpf_table_entry_free(&entry);
    psabpf_table_entry_ctx_free(&ctx);
    psabpf_context_free(&psabpf_ctx);

    return error_code;
}

int do_table_help(int argc, char **argv)
{
    (void) argc; (void) argv;

    fprintf(stderr,
            "Usage: %1$s table add pipe ID TABLE ACTION key MATCH_KEY [data ACTION_PARAMS] [priority PRIORITY]\n"
            "       %1$s table add pipe ID TABLE ref key MATCH_KEY data ACTION_REFS [priority PRIORITY]\n"
            "       %1$s table update pipe ID TABLE ACTION key MATCH_KEY [data ACTION_PARAMS] [priority PRIORITY]\n"
            "       %1$s table delete pipe ID TABLE [key MATCH_KEY]\n"
            "Unimplemented commands:\n"
            "       %1$s table get pipe ID TABLE [key MATCH_KEY]\n"
            "       %1$s table default pipe ID TABLE set ACTION [data ACTION_PARAMS]\n"
            "       %1$s table default pipe ID TABLE\n"
            /* for far future */
            "       %1$s table timeout pipe ID TABLE set { on TTL | off }\n"
            "       %1$s table timeout pipe ID TABLE\n"
            "\n"
            "       TABLE := { id TABLE_ID | name FILE | TABLE_FILE }\n"
            "       ACTION := { id ACTION_ID | ACTION_NAME }\n"
            "       ACTION_REFS := { MEMBER_REF | group GROUP_REF } \n"
            "       MATCH_KEY := { EXACT_KEY | LPM_KEY | RANGE_KEY | TERNARY_KEY | none }\n"
            "       EXACT_KEY := { DATA }\n"
            "       LPM_KEY := { DATA/PREFIX_LEN }\n"
            /* note: simple_switch_CLI uses '->' for range match, but this is
             *   harder to write in a CLI (needs an escape sequence) */
            "       RANGE_KEY := { DATA_MIN..DATA_MAX }\n"
            /* note: by default '&&&' is used but it also will require
             *   an escape sequence in a CLI, so lets use '^' instead */
            "       TERNARY_KEY := { DATA^MASK }\n"
            "       ACTION_PARAMS := { DATA | counter COUNTER_NAME COUNTER_VALUE }\n"
            "       COUNTER_VALUE := { BYTES | PACKETS | BYTES:PACKETS }\n"
            "",
            program_name);
    return 0;
}
