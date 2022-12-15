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

#include <endian.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmp.h>  /* GNU LGPL v3 or GNU GPL v2, used only by function convert_number_to_bytes() */
#include <jansson.h>

#include <nikss_pipeline.h>

#include "common.h"

bool is_keyword(const char *word, const char *str)
{
    if (!word) {
        return false;
    }

    if (strlen(word) != strlen(str)) {
        return false;
    }

    return !memcmp(str, word, strlen(str));
}

int parse_pipeline_id(int *argc, char ***argv, nikss_context_t * nikss_ctx)
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

    char *endptr = NULL;
    nikss_pipeline_id_t id = strtoul(**argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", **argv);
        return EINVAL;
    }
    nikss_context_set_pipeline(nikss_ctx, id);

    if (!nikss_pipeline_exists(nikss_ctx)) {
        fprintf(stderr, "pipeline with given id %u does not exist or is inaccessible\n", id);
        return ENOENT;
    }

    NEXT_ARGP();

    return NO_ERROR;
}

int parse_keyword_value_pairs(int *argc, char ***argv, parser_keyword_value_pair_t *kv_pairs)
{
    for (int i = 0; kv_pairs[i].keyword != NULL; i++) {
        if (is_keyword(**argv, kv_pairs[i].keyword)) {
            NEXT_ARGP_RET();

            char *ptr = NULL;
            uint32_t value = strtoul(**argv, &ptr, 0);
            if (*ptr) {
                fprintf(stderr, "%s: can't parse '%s'\n", kv_pairs[i].comment, **argv);
                return EINVAL;
            }

            if (kv_pairs[i].dst_size == sizeof(uint32_t)) {
                *((uint32_t *) kv_pairs[i].destination) = (uint32_t) value;  /* NOLINT(google-readability-casting): for readability explicitly show type */
            } else if (kv_pairs[i].dst_size == sizeof(uint16_t)) {
                *((uint16_t *) kv_pairs[i].destination) = (uint16_t) value;
            } else if (kv_pairs[i].dst_size == sizeof(uint8_t)) {
                *((uint8_t *) kv_pairs[i].destination) = (uint8_t) value;
            } else {
                fprintf(stderr, "BUG: type width not supported\n");
                return EPERM;
            }

            NEXT_ARGP();
        } else if (kv_pairs[i].required == true) {
            fprintf(stderr, "%s: expected keyword '%s', got '%s'\n",
                    kv_pairs[i].comment, kv_pairs[i].keyword, (**argv != NULL) ? **argv : "");
            return EINVAL;
        }
    }

    return NO_ERROR;
}

/******************************************************************************
 * JSON related functions
 *****************************************************************************/

/* NOLINTNEXTLINE(misc-no-recursion): this is the simplest way to build JSON tree */
int build_struct_json(void *json_parent, void *ctx, void *entry, get_next_field_func_t get_next_field)
{
    nikss_struct_field_t *field = NULL;
    while ((field = get_next_field(ctx, entry)) != NULL) {
        /* To build flat structure of output JSON just remove this and next conditional
         * statement. In other words, preserve only condition and instructions below it:
         *      if (nikss_digest_get_field_type(field) != DIGEST_FIELD_TYPE_DATA) continue; */
        if (nikss_struct_get_field_type(field) == NIKSS_STRUCT_FIELD_TYPE_STRUCT_START) {
            json_t *sub_struct = json_object();
            if (sub_struct == NULL) {
                fprintf(stderr, "failed to prepare message sub-object JSON\n");
                return ENOMEM;
            }
            if (json_object_set(json_parent, nikss_struct_get_field_name(field), sub_struct)) {
                fprintf(stderr, "failed to add message sub-object JSON\n");
                json_decref(sub_struct);
                return EPERM;
            }

            int ret = build_struct_json(sub_struct, ctx, entry, get_next_field);
            json_decref(sub_struct);
            if (ret != NO_ERROR) {
                return ret;
            }

            continue;
        }

        if (nikss_struct_get_field_type(field) == NIKSS_STRUCT_FIELD_TYPE_STRUCT_END) {
            return NO_ERROR;
        }

        if (nikss_struct_get_field_type(field) != NIKSS_STRUCT_FIELD_TYPE_DATA) {
            continue;
        }

        const char *encoded_data = convert_bin_data_to_hexstr(nikss_struct_get_field_data(field),
                                                              nikss_struct_get_field_data_len(field));
        if (encoded_data == NULL) {
            fprintf(stderr, "not enough memory\n");
            return ENOMEM;
        }
        const char *field_name = nikss_struct_get_field_name(field);
        if (field_name == NULL) {
            field_name = "";
        }
        json_object_set_new(json_parent, field_name, json_string(encoded_data));
        free((void *) encoded_data);
    }

    return NO_ERROR;
}

/******************************************************************************
 * Data translation functions to byte stream
 *****************************************************************************/

static int update_context(const char *data, size_t len, void *ctx, enum destination_ctx_type_t ctx_type)
{
    switch (ctx_type) {  /* NOLINT(hicpp-multiway-paths-covered): do not add default branch so clang-tidy can warn about unimplemented support for new context type */
        case CTX_MATCH_KEY:
            return nikss_matchkey_data(ctx, data, len);

        case CTX_MATCH_KEY_TERNARY_MASK:
            return nikss_matchkey_mask(ctx, data, len);

        case CTX_ACTION_DATA:
            return nikss_action_param_create(ctx, data, len);

        case CTX_METER_INDEX:
            return nikss_meter_entry_index(ctx, data, len);

        case CTX_COUNTER_KEY:
            return nikss_counter_entry_set_key(ctx, data, len);

        case CTX_REGISTER_INDEX:
            return nikss_register_entry_set_key(ctx, data, len);

        case CTX_REGISTER_DATA:
            return nikss_register_entry_set_value(ctx, data, len);
    }

    return EPERM;
}

static bool is_valid_mac_address(const char * data)
{
    if (strlen(data) != 2*6+5)  /* 11:22:33:44:55:66 */{
        return false;
    }

    unsigned digits = 0;
    unsigned separators = 0;
    unsigned pos = 0;
    const unsigned separator_pos[] = {2, 5, 8, 11, 14};
    while (*data) {
        if (separators < 5 && pos == separator_pos[separators]) {
            if ((*data != ':') && (*data != '-')) {
                return false;
            }
            separators++;
        } else if (isxdigit(*data)) {
            digits++;
        } else {
            return false;
        }
        data++; pos++;
    }

    return separators == 5 && digits == 12;
}

static int convert_number_to_bytes(const char *data, void *ctx, enum destination_ctx_type_t ctx_type)
{
    mpz_t number;  /* converts any precision number to stream of bytes */
    size_t len = 0;
    size_t forced_len = 0;
    char * buffer = NULL;
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
        if (part_byte != 0) {
            forced_len += 1;
        }
    }

    mpz_init(number);
    if (mpz_set_str(number, data, 0) != 0) {
        fprintf(stderr, "%s: failed to parse number\n", data);
        goto free_gmp;
    }

    len = mpz_sizeinbase(number, 16);
    if (len % 2 != 0) {
        len += 1;
    }
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
    struct in_addr sa_buffer;
    if (inet_pton(AF_INET, data, &sa_buffer) == 1) {
        sa_buffer.s_addr = htonl(sa_buffer.s_addr);
        return update_context((void *) &sa_buffer, sizeof(sa_buffer), ctx, ctx_type);
    }

    /* Try parse as a IPv6 */
    uint64_t ipv6_addr[2];
    if (inet_pton(AF_INET6, data, &ipv6_addr[0]) == 1) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
        /* Swap byte order */
        uint64_t tmp = be64toh(ipv6_addr[0]);
        ipv6_addr[0] = be64toh(ipv6_addr[1]);
        ipv6_addr[1] = tmp;
#endif
        return update_context((void *) &ipv6_addr, sizeof(ipv6_addr), ctx, ctx_type);
    }

    /* Try parse as a MAC address */
    if (is_valid_mac_address(data)) {
        unsigned int v[6];
        if (sscanf(data, "%x%*c%x%*c%x%*c%x%*c%x%*c%x",  /* NOLINT(cert-err34-c): we can ignore errors because string has been validated */
                   &(v[0]), &(v[1]), &(v[2]), &(v[3]), &(v[4]), &(v[5])) == 6) {
            uint8_t bytes[6];
            for (int i = 0; i < 6; i++) {
                bytes[i] = (uint8_t) v[5 - i];
            }
            return update_context((void *) &(bytes[0]), 6, ctx, ctx_type);
        }
    }

    /* Last chance: parse as number */
    return convert_number_to_bytes(data, ctx, ctx_type);
}

char * convert_bin_data_to_hexstr(const void *data, size_t len)
{
    if (data == NULL) {
        return NULL;
    }

    size_t buff_len = len * 2 + 2 + 1; /* 2 characters per byte, prefix, null terminator */
    char *buff = calloc(1, buff_len);
    if (buff == NULL) {
        return NULL;
    }

    buff[0] = '0';
    if (len < 1) {
        return buff;
    }
    buff[1] = 'x';

    const char *half_byte_map = "0123456789abcdef";
    size_t buff_pos = 2;
    size_t data_pos = len;
    bool zero_skip_allowed = true;

    for (size_t i = 0; i < len; i++) {
        --data_pos;
        unsigned char byte = ((const unsigned char *) data)[data_pos];
        char upper = half_byte_map[(byte >> 4) & 0xF];
        char lower = half_byte_map[byte & 0xF];

        if (upper != '0' || !zero_skip_allowed) {
            zero_skip_allowed = false;
            buff[buff_pos++] = upper;
        }

        if (lower != '0' || !zero_skip_allowed || data_pos == 0) {
            zero_skip_allowed = false;
            buff[buff_pos++] = lower;
        }
    }

    return buff;
}

static json_t *create_json_match_key(nikss_match_key_t *mk)
{
    json_t *root = json_object();
    if (root == NULL) {
        return NULL;
    }

    char *value_str = convert_bin_data_to_hexstr(nikss_matchkey_get_data(mk), nikss_matchkey_get_data_size(mk));
    char *mask_str = convert_bin_data_to_hexstr(nikss_matchkey_get_mask(mk), nikss_matchkey_get_mask_size(mk));
    bool failed = false;

    switch (nikss_matchkey_get_type(mk)) {
        case NIKSS_EXACT:
            json_object_set_new(root, "type", json_string("exact"));
            if (value_str != NULL) {
                json_object_set_new(root, "value", json_string(value_str));
            } else {
                failed = true;
            }
            break;

        case NIKSS_LPM:
            json_object_set_new(root, "type", json_string("lpm"));
            if (value_str != NULL) {
                json_object_set_new(root, "value", json_string(value_str));
            } else {
                failed = true;
            }
            json_object_set_new(root, "prefix_len", json_integer(nikss_matchkey_get_prefix_len(mk)));
            break;

        case NIKSS_TERNARY:
            json_object_set_new(root, "type", json_string("ternary"));
            if (value_str != NULL && mask_str != NULL) {
                json_object_set_new(root, "value", json_string(value_str));
                json_object_set_new(root, "mask", json_string(mask_str));
            } else {
                failed = true;
            }
            break;

        default:
            json_object_set_new(root, "type", json_string("unknown"));
    }

    if (failed) {
        fprintf(stderr, "failed to parse match key\n");
        json_decref(root);
        root = NULL;
    }

    if (value_str != NULL) {
        free(value_str);
    }
    if (mask_str != NULL) {
        free(mask_str);
    }

    return root;
}

json_t *create_json_entry_key(nikss_table_entry_t *entry)
{
    json_t *keys = json_array();
    if (keys == NULL) {
        return NULL;
    }

    nikss_match_key_t *mk = NULL;
    while ((mk = nikss_table_entry_get_next_matchkey(entry)) != NULL) {
        json_t *key_entry = create_json_match_key(mk);
        if (key_entry == NULL) {
            json_decref(keys);
            return NULL;
        }
        json_array_append_new(keys, key_entry);
        nikss_matchkey_free(mk);
    }

    return keys;
}

int parse_key_data(int *argc, char ***argv, nikss_table_entry_t *entry)
{
    bool has_any_key = false;
    /* cppcheck-suppress unreadVariable */
    int error_code = NO_ERROR;

    do {
        NEXT_ARGP_RET();
        if (**argv[0] == 0) {
            return EINVAL;  /* should never occur because of above check, added for clang-tidy */
        }

        if (is_keyword(**argv, "data") || is_keyword(**argv, "priority")) {
            return NO_ERROR;
        }

        if (is_keyword(**argv, "none")) {
            if (!has_any_key) {
                NEXT_ARGP();
                return NO_ERROR;
            }

            fprintf(stderr, "Unexpected none key\n");
            return EPERM;
        }

        nikss_match_key_t mk;
        nikss_matchkey_init(&mk);
        char *substr_ptr = NULL;
        if ((substr_ptr = strstr(**argv, "/")) != NULL) {
            nikss_matchkey_type(&mk, NIKSS_LPM);
            *(substr_ptr++) = 0;
            if (*substr_ptr == 0) {
                fprintf(stderr, "missing prefix length for LPM key\n");
                return EINVAL;
            }
            error_code = translate_data_to_bytes(**argv, &mk, CTX_MATCH_KEY);
            if (error_code != NO_ERROR) {
                return error_code;
            }
            char *ptr = NULL;
            nikss_matchkey_prefix_len(&mk, strtoul(substr_ptr, &ptr, 0));
            if (*ptr) {
                fprintf(stderr, "%s: unable to parse prefix length\n", substr_ptr);
                return EINVAL;
            }
        } else if (strstr(**argv, "..") != NULL) {
            fprintf(stderr, "range match key not supported yet\n");
            return ENOTSUP;
        } else if ((substr_ptr = strstr(**argv, "^")) != NULL) {
            nikss_matchkey_type(&mk, NIKSS_TERNARY);
            /* Split data and mask */
            *substr_ptr = 0;
            substr_ptr++;
            if (*substr_ptr == 0) {
                fprintf(stderr, "missing mask for ternary key\n");
                return EINVAL;
            }
            error_code = translate_data_to_bytes(**argv, &mk, CTX_MATCH_KEY);
            if (error_code != NO_ERROR) {
                return error_code;
            }
            error_code = translate_data_to_bytes(substr_ptr, &mk, CTX_MATCH_KEY_TERNARY_MASK);
            if (error_code != NO_ERROR) {
                return error_code;
            }
        } else {
            nikss_matchkey_type(&mk, NIKSS_EXACT);
            error_code = translate_data_to_bytes(**argv, &mk, CTX_MATCH_KEY);
            if (error_code != NO_ERROR) {
                return error_code;
            }
        }
        error_code = nikss_table_entry_matchkey(entry, &mk);
        nikss_matchkey_free(&mk);
        if (error_code != NO_ERROR) {
            return error_code;
        }

        has_any_key = true;
    } while ((*argc) > 1);
    NEXT_ARGP();

    return NO_ERROR;
}
