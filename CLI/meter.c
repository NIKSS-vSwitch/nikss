#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "../include/psabpf.h"
#include "meter.h"

/******************************************************************************
 * Command line parsing functions
 *****************************************************************************/

int convert_str_to_meter_value(const char *str, psabpf_meter_value_t *value) {
    char * end_ptr = NULL;
    *value = strtoull(str, &end_ptr, 0);
    if (*value == 0 || end_ptr == NULL) {
        fprintf(stderr, "%s: failed to parse value\n", str);
        return EINVAL;
    }
    return NO_ERROR;
}

int parse_dst_meter(int *argc, char ***argv, psabpf_context_t *psabpf_ctx,
                    psabpf_meter_ctx_t *ctx)
{
    if (is_keyword(**argv, "id")) {
        NEXT_ARGP_RET();
        fprintf(stderr, "id: meter access not supported\n");
        return ENOTSUP;
    } else if (is_keyword(**argv, "name")) {
        NEXT_ARGP_RET();
        fprintf(stderr, "name: meter access not supported yet\n");
        return ENOTSUP;
    } else {
        int error_code = psabpf_meter_ctx_name(ctx, psabpf_ctx, **argv);
        if (error_code != NO_ERROR)
            return error_code;
    }

    NEXT_ARGP_RET();

    return NO_ERROR;
}

int parse_meter_index(int *argc, char ***argv, psabpf_meter_entry_t *entry) {
    int error_code = NO_ERROR;

    if (!is_keyword(**argv, "index"))
        return EPERM;

    NEXT_ARGP_RET();

    error_code = translate_data_to_bytes(**argv, entry, CTX_METER_INDEX);
    if (error_code != NO_ERROR)
        return error_code;

    return NO_ERROR;
}

int parse_meter_data(int *argc, char ***argv, psabpf_meter_entry_t *entry) {
    NEXT_ARGP_RET();

    int error_code = NO_ERROR;
    char *delimiter = ":";
    char *pir_str = strsep(*argv, delimiter);
    char *pbs_str = strsep(*argv, delimiter);
    if (pbs_str == NULL) {
        fprintf(stderr, "%s: invalid format. Use PIR:PBS\n", pir_str);
        return EINVAL;
    }

    NEXT_ARGP_RET();

    char *cir_str = strsep(*argv, delimiter);
    char *cbs_str = strsep(*argv, delimiter);
    if (cbs_str == NULL) {
        fprintf(stderr, "%s: invalid format. Use CIR:CBS\n", cir_str);
        return EINVAL;
    }

    psabpf_meter_value_t pir;
    error_code = convert_str_to_meter_value(pir_str, &pir);
    if (error_code != NO_ERROR)
        return error_code;

    psabpf_meter_value_t pbs;
    error_code = convert_str_to_meter_value(pbs_str, &pbs);
    if (error_code != NO_ERROR)
        return error_code;

    psabpf_meter_value_t cir;
    error_code = convert_str_to_meter_value(cir_str, &cir);
    if (error_code != NO_ERROR)
        return error_code;

    psabpf_meter_value_t cbs;
    error_code = convert_str_to_meter_value(cbs_str, &cbs);
    if (error_code != NO_ERROR)
        return error_code;

    return psabpf_meter_entry_data(entry, pir, pbs, cir, cbs);
}

/******************************************************************************
 * Command line meter functions
 *****************************************************************************/

int do_meter_get(int argc, char **argv) {
    psabpf_meter_entry_t entry;
    psabpf_meter_ctx_t meter_ctx;
    psabpf_context_t psabpf_ctx;
    int error_code = EPERM;

    psabpf_meter_entry_init(&entry);
    psabpf_meter_ctx_init(&meter_ctx);
    psabpf_context_init(&psabpf_ctx);

    /* 0. Get the pipeline id */
    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR)
        goto clean_up;

    /* 1. Get meter */
    if (parse_dst_meter(&argc, &argv, &psabpf_ctx, &meter_ctx) != NO_ERROR)
        goto clean_up;

    /* 2. Get index */
    if (parse_meter_index(&argc, &argv, &entry) != NO_ERROR)
        goto clean_up;

    /* 3. Get meter value */
    if (psabpf_meter_ctx_get(&meter_ctx, &entry) != NO_ERROR)
        goto clean_up;

    /* 4. Display meter entry */
    fprintf(stderr, "pir=%lu, pbs=%lu, cir=%lu, cbs=%lu\n",
            entry.pir, entry.pbs, entry.cir, entry.cbs);
    error_code = NO_ERROR;

clean_up:
    psabpf_meter_entry_free(&entry);
    psabpf_meter_ctx_free(&meter_ctx);
    psabpf_context_free(&psabpf_ctx);
    return error_code;
}

int do_meter_update(int argc, char **argv) {
    psabpf_meter_entry_t entry;
    psabpf_meter_ctx_t meter_ctx;
    psabpf_context_t psabpf_ctx;
    int error_code = EPERM;

    psabpf_meter_entry_init(&entry);
    psabpf_meter_ctx_init(&meter_ctx);
    psabpf_context_init(&psabpf_ctx);

    /* 0. Get the pipeline id */
    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR)
        goto clean_up;

    /* 1. Get meter */
    if (parse_dst_meter(&argc, &argv, &psabpf_ctx, &meter_ctx) != NO_ERROR)
        goto clean_up;

    /* 2. Get index */
    if (parse_meter_index(&argc, &argv, &entry) != NO_ERROR)
        goto clean_up;

    /* 3. Get meter parameters */
    if (parse_meter_data(&argc, &argv, &entry) != NO_ERROR)
        goto clean_up;

    error_code = psabpf_meter_ctx_update(&meter_ctx, &entry);

clean_up:
    psabpf_meter_entry_free(&entry);
    psabpf_meter_ctx_free(&meter_ctx);
    psabpf_context_free(&psabpf_ctx);
    return error_code;
}

int do_meter_reset(int argc, char **argv) {
    psabpf_meter_entry_t entry;
    psabpf_meter_ctx_t meter_ctx;
    psabpf_context_t psabpf_ctx;
    int error_code = EPERM;

    psabpf_meter_entry_init(&entry);
    psabpf_meter_ctx_init(&meter_ctx);
    psabpf_context_init(&psabpf_ctx);

    /* 0. Get the pipeline id */
    if (parse_pipeline_id(&argc, &argv, &psabpf_ctx) != NO_ERROR)
        goto clean_up;

    /* 1. Get meter */
    if (parse_dst_meter(&argc, &argv, &psabpf_ctx, &meter_ctx) != NO_ERROR)
        goto clean_up;

    /* 2. Get index */
    if (parse_meter_index(&argc, &argv, &entry) != NO_ERROR)
        goto clean_up;

    error_code = psabpf_meter_ctx_reset(&meter_ctx, &entry);

clean_up:
    psabpf_meter_entry_free(&entry);
    psabpf_meter_ctx_free(&meter_ctx);
    psabpf_context_free(&psabpf_ctx);
    return error_code;
}

int do_meter_help(int argc, char **argv) {
    (void) argc; (void) argv;

    fprintf(stderr,
            "Usage: %1$s meter get pipe ID METER index INDEX\n"
            "       %1$s meter update pipe ID METER index INDEX PIR:PBS CIR:CBS\n"
            "       %1$s meter reset pipe ID METER index INDEX\n"
            "\n"
            "       METER := { id METER_ID | name FILE | METER_FILE }\n"
            "       INDEX := { DATA }\n"
            "       PIR := { DATA }\n"
            "       PBS := { DATA }\n"
            "       CIR := { DATA }\n"
            "       CBS := { DATA }\n"
            "",
            program_name);
    return 0;
}