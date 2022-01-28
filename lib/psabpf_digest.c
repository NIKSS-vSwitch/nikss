#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <bpf/bpf.h>

#include <psabpf.h>
#include <psabpf_digest.h>

#include "btf.h"
#include "common.h"

void psabpf_digest_context_init(psabpf_digest_context_t *ctx)
{
    if (ctx == NULL)
        return;
    memset(ctx, 0, sizeof(psabpf_digest_context_t));

    ctx->queue.fd = -1;
    ctx->btf_metadata.associated_prog = -1;
}

void psabpf_digest_context_free(psabpf_digest_context_t *ctx)
{
    if (ctx == NULL)
        return;

    free_btf(&ctx->btf_metadata);
    close_object_fd(&(ctx->queue.fd));
}

//static int parse_digest_btf(psabpf_digest_context_t *ctx)
//{
//    uint32_t type_id = psabtf_get_member_type_id_by_name(ctx->btf_metadata.btf, ctx->queue.btf_type_id, "value");
//
//    if (type_id == 0) {
//        fprintf(stderr, "warning: BTF type not found for digest, placing all the data in a single field\n");
//
//        ctx->field_name = malloc(sizeof(const char *));
//        ctx->field_len = calloc(1, sizeof(size_t));
//        ctx->data_offset = calloc(1, sizeof(size_t));
//        if (ctx->field_name == NULL || ctx->field_len == NULL || ctx->data_offset == NULL) {
//            fprintf(stderr, "not enough memory\n");
//            return ENOMEM;
//        }
//
//        /* must be malloc'ed because later we assume all fields are dynamically allocated */
//        ctx->field_name[0] = strdup("data");
//        if (ctx->field_name[0] == NULL) {
//            fprintf(stderr, "not enough memory\n");
//            return ENOMEM;
//        }
//
//        ctx->field_len[0] = ctx->queue.value_size;
//        ctx->data_offset[0] = 0;
//        ctx->n_fields = 1;
//    } else {
//        /* Copy from BTF */
//        const struct btf_type *type = psabtf_get_type_by_id(ctx->btf_metadata.btf, type_id);
//        if (type == NULL) {
//            fprintf(stderr, "invalid BTF type\n");
//            return EINVAL;
//        }
//
//        unsigned entries = btf_vlen(type);
//        ctx->field_name = calloc(entries, sizeof(const char *));
//        ctx->field_len = calloc(entries, sizeof(size_t));
//        ctx->data_offset = calloc(entries, sizeof(size_t));
//        if (ctx->field_name == NULL || ctx->field_len == NULL || ctx->data_offset == NULL) {
//            fprintf(stderr, "not enough memory\n");
//            return ENOMEM;
//        }
//
//        for (unsigned i = 0; i < entries; i++) {
//            psabtf_struct_member_md_t md;
//            if (psabtf_get_member_md_by_index(ctx->btf_metadata.btf, type_id, i, &md)) {
//                fprintf(stderr, "invalid field or type\n");
//                return EINVAL;
//            }
//            const char *field_name = btf__name_by_offset(ctx->btf_metadata.btf, md.member->name_off);
//            if (field_name == NULL) {
//                fprintf(stderr, "invalid field name\n");
//                return EINVAL;
//            }
//
//            ctx->field_name[i] = strdup(field_name);
//            if (ctx->field_name[i] == NULL) {
//                fprintf(stderr, "not enough memory\n");
//                return ENOMEM;
//            }
//            ctx->field_len[i] = psabtf_get_type_size_by_id(ctx->btf_metadata.btf, md.effective_type_id);
//            ctx->field_len[i] = md.bit_offset / 8;
//        }
//
//        ctx->n_fields = entries;
//    }
//
//    return NO_ERROR;
//}

int psabpf_digest_open(psabpf_context_t *psabpf_ctx, psabpf_digest_context_t *ctx, const char *name)
{
    if (psabpf_ctx == NULL || ctx == NULL || name == NULL)
        return EINVAL;

    /* get the BTF, it is optional so print only warning */
    if (load_btf(psabpf_ctx, &ctx->btf_metadata) != NO_ERROR)
        fprintf(stderr, "warning: couldn't find BTF info\n");

    char base_path[256];
    build_ebpf_map_path(base_path, sizeof(base_path), psabpf_ctx);
    int ret = open_bpf_map(&ctx->btf_metadata, name, base_path, &ctx->queue);
    if (ret != NO_ERROR)
        return ret;

    if (ctx->queue.type != BPF_MAP_TYPE_QUEUE) {
        fprintf(stderr, "%s: not a Digest instance\n", name);
        close_object_fd(&ctx->queue.fd);
        return EOPNOTSUPP;
    }

//    ret = parse_digest_btf(ctx);
//    if (ret != NO_ERROR) {
//        fprintf(stderr, "failed to obtain fields names\n");
//        return ret;
//    }

    return NO_ERROR;
}

int psabpf_digest_get_next(psabpf_digest_context_t *ctx, psabpf_digest_t *digest)
{
    if (ctx == NULL || digest == NULL)
        return EINVAL;

    memset(digest, 0, sizeof(psabpf_digest_t));

    if (ctx->queue.fd < 0)
        return EBADF;

    digest->raw_data = malloc(ctx->queue.value_size);
    if (digest->raw_data == NULL) {
        fprintf(stderr, "not enough memory\n");
        return ENOMEM;
    }

    int ret = bpf_map_lookup_and_delete_elem(ctx->queue.fd, NULL, digest->raw_data);
    if (ret != 0) {
        ret = errno;
        if (ret != ENOENT)
            fprintf(stderr, "failed to pop element from queue: %s\n", strerror(ret));
        return ret;
    }

    /* TODO: field pointers */

    return NO_ERROR;
}

void psabpf_digest_free(psabpf_digest_t *digest)
{
    if (digest == NULL)
        return;

    if (digest->raw_data != NULL)
        free(digest->raw_data);

    memset(digest, 0, sizeof(psabpf_digest_t));
}

psabpf_digest_field_t * psabpf_digest_get_next_field(psabpf_digest_context_t *ctx, psabpf_digest_t *digest)
{
    return NULL;
}

psabpf_digest_field_type_t psabpf_digest_get_field_type(psabpf_digest_field_t *field)
{
    return DIGEST_FIELD_TYPE_DATA;
}

const char * psabpf_digest_get_field_name(psabpf_digest_field_t *field)
{
    return NULL;
}

const void * psabpf_digest_get_field_data(psabpf_digest_field_t *field)
{
    return NULL;
}

size_t psabpf_digest_get_field_data_len(psabpf_digest_field_t *field)
{
    return 0;
}
