#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <jansson.h>

#include <psabpf_digest.h>
#include "digest.h"

/* TODO: use GMP */
char * convert_data_to_hexstr(const void *data, size_t len)
{
    size_t buff_len = len * 2 + 2 + 1; /* 2 characters per byte, prefix, null terminator */
    char *buff = malloc(buff_len);
    if (buff == NULL)
        return NULL;

    memset(buff, 0, buff_len);
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

static int build_struct_json(json_t *parent, psabpf_digest_context_t *ctx, psabpf_digest_t *digest)
{
    psabpf_digest_field_t *field;
    while ((field = psabpf_digest_get_next_field(ctx, digest)) != NULL) {
        /* To build flat structure of output JSON just remove this and next conditional
         * statement. In other words, preserve only condition and instructions below it:
         *      if (psabpf_digest_get_field_type(field) != DIGEST_FIELD_TYPE_DATA) continue; */
        if (psabpf_digest_get_field_type(field) == DIGEST_FIELD_TYPE_STRUCT_START) {
            json_t *sub_struct = json_object();
            json_object_set(parent, psabpf_digest_get_field_name(field), sub_struct);

            build_struct_json(sub_struct, ctx, digest);

            json_decref(sub_struct);
            continue;
        }

        if (psabpf_digest_get_field_type(field) == DIGEST_FIELD_TYPE_STRUCT_END)
            return 0;

        if (psabpf_digest_get_field_type(field) != DIGEST_FIELD_TYPE_DATA)
            continue;

        const char *encoded_data = convert_data_to_hexstr(psabpf_digest_get_field_data(field),
                                                          psabpf_digest_get_field_data_len(field));
        if (encoded_data == NULL)
            continue;
        json_object_set_new(parent, psabpf_digest_get_field_name(field), json_string(encoded_data));
        free((void *) encoded_data);
    }

    return 0;
}

int do_digest_get(int argc, char **argv)
{
    (void) argc; (void) argv;

    psabpf_context_t psabpf_ctx;
    psabpf_digest_context_t ctx;

    psabpf_context_init(&psabpf_ctx);
    psabpf_digest_context_init(&ctx);

    psabpf_context_set_pipeline(&psabpf_ctx, 999);

    psabpf_digest_open(&psabpf_ctx, &ctx, "mac_learn_digest_0");

    json_t *root = json_object();
    json_t *extern_type = json_object();
    json_t *instance_name = json_object();
    json_t *entries = json_array();

    json_object_set(instance_name, "digests", entries);
    json_object_set_new(extern_type, "mac_learn_digest_0", instance_name);
    json_object_set_new(root, "Digest", extern_type);

    psabpf_digest_t digest;
    while (psabpf_digest_get_next(&ctx, &digest) == NO_ERROR) {
        json_t *entry = json_object();
        build_struct_json(entry, &ctx, &digest);
        json_array_append_new(entries, entry);

        psabpf_digest_free(&digest);
    }
    psabpf_digest_free(&digest);

    json_dumpf(root, stdout, JSON_INDENT(4) | JSON_ENSURE_ASCII);
    json_decref(entries);
    json_decref(root);

    psabpf_digest_context_free(&ctx);
    psabpf_context_free(&psabpf_ctx);

    return 0;
}

int do_digest_help(int argc, char **argv)
{
    (void) argc; (void) argv;
    return 0;
}
