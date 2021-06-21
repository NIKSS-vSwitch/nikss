#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <gmp.h>  /* GNU LGPL v3 or GNU GPL v2, used only by function convert_number_to_bytes() */

#include "../include/psabpf.h"
#include "table.h"

/******************************************************************************
 * Data translation functions to byte stream
 *****************************************************************************/

enum destination_ctx_type_t {
    CTX_MATCH_KEY,
    CTX_ACTION_DATA
};

int update_context(const char *data, size_t len, void *ctx, enum destination_ctx_type_t ctx_type)
{
    if (ctx_type == CTX_MATCH_KEY)
        return psabpf_matchkey_data(ctx, data, len);
    else if (ctx_type == CTX_ACTION_DATA)
        return psabpf_action_param_create(ctx, data, len);

    return -1;
}

/* TODO: Is there any ready to use function for this purpose? */
bool is_valid_mac_address(const char * data)
{
    if (strlen(data) != 2*6+5)  /* 11:22:33:44:55:66 */
        return false;

    unsigned digits = 0, separators = 0, pos = 0;
    unsigned separator_pos[] = {2, 5, 8, 11, 14};
    while (*data) {
        if (pos == separator_pos[separators]) {
            if ((*data != ':') && (*data != '-'))
                return false;
            separators++;
        } else if (isxdigit(*data)) {
            digits++;
        } else {
            return false;
        }
        if (separators > 5 || digits > 12)
            return false;
        data++; pos++;
    }
    return true;
}

int convert_number_to_bytes(const char *data, void *ctx, enum destination_ctx_type_t ctx_type)
{
    mpz_t number;  /* converts any precision number to stream of bytes */
    size_t len, forced_len = 0;
    char * buffer;
    int error_code = -EPERM;

    /* try find width specification */
    if (strstr(data, "w") != NULL) {
        char * end_ptr = NULL;
        forced_len = strtoul(data, &end_ptr, 0);
        if (forced_len == 0 || end_ptr == NULL) {
            fprintf(stderr, "%s: failed to parse width\n", data);
            return -EPERM;
        }
        if (strlen(end_ptr) <= 1) {
            fprintf(stderr, "%s: failed to parse width (no data after width)\n", data);
            return -EPERM;
        }
        if (end_ptr[0] != 'w') {
            fprintf(stderr, "%s: failed to parse width (wrong format)\n", data);
            return -EPERM;
        }
        data = end_ptr + 1;
        size_t part_byte = forced_len % 8;
        forced_len = forced_len / 8;
        if (part_byte != 0)
            forced_len += 1;
    }

    mpz_init(number);
    if (mpz_set_str(number, data, 0) != 0) {
        fprintf(stderr, "%s: failed to parse number\n", data);
        goto free_gmp;
    }

    len = mpz_sizeinbase(number, 16);
    if (len % 2 != 0)
        len += 1;
    len /= 2;  /* two digits per byte */

    if (forced_len != 0) {
        if (len > forced_len) {
            fprintf(stderr, "%s: do not fits into %zu bytes\n", data, forced_len);
            goto free_gmp;
        }
        len = forced_len;
    }

    buffer = malloc(len);
    if (buffer == NULL) {
        fprintf(stderr, "not enough memory\n");
        goto free_gmp;
    }
    /* when data is "0", gmp may not write any value */
    memset(buffer, 0, len);
    mpz_export(buffer, 0, -1, 1, 0, 0, number);

    error_code = update_context(buffer, len, ctx, ctx_type);

    free(buffer);
free_gmp:
    mpz_clear(number);

    return error_code;
}

int translate_data_to_bytes(const char *data, void *ctx, enum destination_ctx_type_t ctx_type)
{
    /* Try parse as a IPv4 */
    struct sockaddr_in sa_buffer;
    if (inet_pton(AF_INET, data, &(sa_buffer.sin_addr)) == 1) {
        sa_buffer.sin_addr.s_addr = htonl(sa_buffer.sin_addr.s_addr);
        return update_context((void *) &(sa_buffer.sin_addr), sizeof(sa_buffer.sin_addr), ctx, ctx_type);
    }

    /* TODO: Try parse IPv6 (similar to IPv4) */

    /* Try parse as a MAC address */
    if (is_valid_mac_address(data)) {
        int v[6];
        if (sscanf(data, "%x%*c%x%*c%x%*c%x%*c%x%*c%x",
                   &(v[0]), &(v[1]), &(v[2]), &(v[3]), &(v[4]), &(v[5])) == 6) {
            uint8_t bytes[6];
            for (int i = 0; i < 6; i++)
                bytes[i] = (uint8_t) v[5-i];
            return update_context((void *) &(bytes[0]), 6, ctx, ctx_type);
        }
    }

    /* Last chance: parse as number */
    return convert_number_to_bytes(data, ctx, ctx_type);
}

/******************************************************************************
 * Command line parsing functions
 *****************************************************************************/

int parse_dst_table(int *argc, char ***argv, psabpf_context_t *psabpf_ctx,
                    psabpf_table_entry_ctx_t *ctx, bool can_be_last)
{
    if (is_keyword(**argv, "id")) {
        NEXT_ARGP_EXIT();
        fprintf(stderr, "id: table access not supported\n");
        return -EPERM;
    } else if (is_keyword(**argv, "name")) {
        NEXT_ARGP_EXIT();
        fprintf(stderr, "name: table access not supported yet\n");
        return -EPERM;
    } else {
        int error_code = psabpf_table_entry_ctx_tblname(psabpf_ctx, ctx, **argv);
        if (error_code != NO_ERROR)
            return error_code;
    }

    if (can_be_last) {
        NEXT_ARGP();
    } else {
        NEXT_ARGP_EXIT();
    }

    return NO_ERROR;
}

int parse_table_action(int *argc, char ***argv, psabpf_table_entry_ctx_t *ctx,
                       psabpf_action_t * action, bool * indirect_table)
{
    *indirect_table = false;

    if (is_keyword(**argv, "id")) {
        NEXT_ARGP_EXIT();
        char *ptr;
        psabpf_action_set_id(action, strtoul(**argv, &ptr, 0));
        if (*ptr) {
            fprintf(stderr, "%s: unable to parse as an action id\n", **argv);
            return -EPERM;
        }
    } else if (is_keyword(**argv, "ref")) {
        *indirect_table = true;
        psabpf_table_entry_ctx_mark_indirect(ctx);
    } else {
        fprintf(stderr, "specify an action by name is not supported yet\n");
        return -EPERM;
    }
    NEXT_ARGP_EXIT();

    return NO_ERROR;
}

int parse_table_key(int *argc, char ***argv, psabpf_table_entry_t *entry)
{
    bool has_any_key = false;
    int error_code = -EPERM;

    if (!is_keyword(**argv, "key"))
        return NO_ERROR;

    do {
        NEXT_ARGP_EXIT();
        if (is_keyword(**argv, "data") || is_keyword(**argv, "priority"))
            return NO_ERROR;

        if (is_keyword(**argv, "none")) {
            if (!has_any_key) {
                fprintf(stderr, "Support for table with empty key not implemented yet\n");
                return -EPERM;
            } else {
                fprintf(stderr, "Unexpected none key\n");
                return -EPERM;
            }
        }

        psabpf_match_key_t mk;
        psabpf_matchkey_init(&mk);
        if (strstr(**argv, "/") != NULL) {
            fprintf(stderr, "lpm match key not supported yet\n");
            return -EPERM;
        } else if (strstr(**argv, "..") != NULL) {
            fprintf(stderr, "range match key not supported yet\n");
            return -EPERM;
        } else if (strstr(**argv, "%") != NULL) {
            fprintf(stderr, "ternary match key not supported yet\n");
            return -EPERM;
        } else {
            psabpf_matchkey_type(&mk, PSABPF_EXACT);
            error_code = translate_data_to_bytes(**argv, &mk, CTX_MATCH_KEY);
            if (error_code != NO_ERROR)
                return error_code;
            error_code = psabpf_table_entry_matchkey(entry, &mk);
        }
        psabpf_matchkey_free(&mk);
        if (error_code != NO_ERROR)
            return error_code;

        has_any_key = true;
    } while ((*argc) > 1);
    NEXT_ARGP();

    return NO_ERROR;
}

int parse_action_data(int *argc, char ***argv,
                      psabpf_action_t *action, bool indirect_table)
{
    if (!is_keyword(**argv, "data")) {
        if (indirect_table) {
            fprintf(stderr, "expected action reference\n");
            return -EPERM;
        }
        return NO_ERROR;
    }

    do {
        NEXT_ARGP_EXIT();
        if (is_keyword(**argv, "priority"))
            return NO_ERROR;

        bool ref_is_group_ref = false;
        if (indirect_table) {
            if (is_keyword(**argv, "group")) {
                ref_is_group_ref = true;
                NEXT_ARGP_EXIT();
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

int parse_entry_priority(int *argc, char ***argv)
{
    if (is_keyword(**argv, "priority")) {
        NEXT_ARGP_EXIT();  /* skip keyword */
        fprintf(stderr, "Priority is not supported\n");
        NEXT_ARGP();  /* skip priority value */
        return -EPERM;
    }
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
    int error_code = -EPERM;
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
    if (parse_action_data(&argc, &argv, &action, table_is_indirect) != NO_ERROR)
        goto clean_up;

    /* 5. Get entry priority */
    if (parse_entry_priority(&argc, &argv) != NO_ERROR)
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
    int error_code = -EPERM;

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
            "       %1$s table del pipe ID TABLE [key MATCH_KEY]\n"
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
            /* note: by default '&&&' is used but it also will requires
             *   an escape sequence in a CLI, so lets use '%' instead */
            "       TERNARY_KEY := { DATA%%MASK }\n"
            "       ACTION_PARAMS := { DATA }\n"
            "",
            program_name);
    return 0;
}
