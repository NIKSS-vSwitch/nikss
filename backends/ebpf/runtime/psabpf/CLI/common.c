#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "common.h"

bool is_keyword(const char *word, const char *str)
{
    if (!word)
        return false;

    if (strlen(word) < strlen(str)) {
        return false;
    }

    return !memcmp(str, word, strlen(str));
}

int parse_pipeline_id(int *argc, char ***argv, psabpf_context_t * psabpf_ctx)
{
    if (*argc < 2) {
        fprintf(stderr, "too few parameters\n");
        return -1;
    }

    if (!is_keyword(**argv, "pipe")) {
        fprintf(stderr, "expected 'pipe' keyword\n");
        return EINVAL;
    }
    NEXT_ARGP();

    char *endptr;
    psabpf_pipeline_id_t id = strtoul(**argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", **argv);
        return EINVAL;
    }
    psabpf_context_set_pipeline(psabpf_ctx, id);

    NEXT_ARGP();

    return NO_ERROR;
}

/******************************************************************************
 * Data translation functions to byte stream
 *****************************************************************************/

static int update_context(const char *data, size_t len, void *ctx, enum destination_ctx_type_t ctx_type)
{
    if (ctx_type == CTX_MATCH_KEY)
        return psabpf_matchkey_data(ctx, data, len);
    else if (ctx_type == CTX_MATCH_KEY_TERNARY_MASK)
        return psabpf_matchkey_mask(ctx, data, len);
    else if (ctx_type == CTX_ACTION_DATA)
        return psabpf_action_param_create(ctx, data, len);
    else if (ctx_type == CTX_METER_INDEX)
        return psabpf_meter_entry_index(ctx, data, len);

    return EPERM;
}

/* TODO: Is there any ready to use function for this purpose? */
static bool is_valid_mac_address(const char * data)
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

static int convert_number_to_bytes(const char *data, void *ctx, enum destination_ctx_type_t ctx_type)
{
    mpz_t number;  /* converts any precision number to stream of bytes */
    size_t len, forced_len = 0;
    char * buffer;
    int error_code = EPERM;

    /* try find width specification */
    if (strstr(data, "w") != NULL) {
        char * end_ptr = NULL;
        forced_len = strtoul(data, &end_ptr, 0);
        if (forced_len == 0 || end_ptr == NULL) {
            fprintf(stderr, "%s: failed to parse width\n", data);
            return EINVAL;
        }
        if (strlen(end_ptr) <= 1) {
            fprintf(stderr, "%s: failed to parse width (no data after width)\n", data);
            return EINVAL;
        }
        if (end_ptr[0] != 'w') {
            fprintf(stderr, "%s: failed to parse width (wrong format)\n", data);
            return EINVAL;
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
