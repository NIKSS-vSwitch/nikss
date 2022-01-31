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

    if (ctx->fields != NULL) {
        for (unsigned i = 0; i < ctx->n_fields; i++) {
            if (ctx->fields[i].name != NULL)
                free((void *) ctx->fields[i].name);
        }

        free(ctx->fields);
        ctx->fields = NULL;
    }
}

static int setup_context_no_btf(psabpf_digest_context_t *ctx)
{
    ctx->fields = calloc(1, sizeof(psabpf_digest_field_descriptor_t));
    if (ctx->fields == NULL) {
        fprintf(stderr, "not enough memory\n");
        return ENOMEM;
    }

    /* must be malloc'ed because later we assume all fields are dynamically allocated */
    ctx->fields[0].name = strdup("data");
    if (ctx->fields[0].name == NULL) {
        fprintf(stderr, "not enough memory\n");
        return ENOMEM;
    }

    ctx->fields[0].data_len = ctx->queue.value_size;
    ctx->fields[0].data_offset = 0;
    ctx->fields[0].type = DIGEST_FIELD_TYPE_DATA;
    ctx->n_fields = 1;

    return NO_ERROR;
}

/* no memory allocation */
static size_t count_total_fields(psabpf_digest_context_t *ctx, uint32_t type_id)
{
    const struct btf_type *type = psabtf_get_type_by_id(ctx->btf_metadata.btf, type_id);
    if (!btf_is_struct(type))
        return 1;

    unsigned entries = btf_vlen(type);

    for (unsigned i = 0; i < entries; i++) {
        psabtf_struct_member_md_t md;
        if (psabtf_get_member_md_by_index(ctx->btf_metadata.btf, type_id, i, &md) != NO_ERROR) {
            fprintf(stderr, "invalid field or type\n");
            return 0;
        }

        const struct btf_type *member_type = psabtf_get_type_by_id(ctx->btf_metadata.btf, md.effective_type_id);
        if (btf_is_struct(member_type)) {
            /* We need two additional entries per struct - for struct start and struct end,
             * but first one is already included as member of parent structure */
            entries = entries + count_total_fields(ctx, md.effective_type_id) + 1;
        }
    }

    return entries;
}

static int parse_digest_struct(psabpf_digest_context_t *ctx, uint32_t type_id, unsigned *field_idx, const size_t base_offset)
{
    const struct btf_type *type = psabtf_get_type_by_id(ctx->btf_metadata.btf, type_id);
    if (type == NULL) {
        fprintf(stderr, "invalid type id: %u\n", type_id);
        return EINVAL;
    }

    if (!btf_is_struct(type)) {
        fprintf(stderr, "invalid digest type: expected struct\n");
        return EINVAL;
    }

    unsigned entries = btf_vlen(type);
    for (unsigned i = 0; i < entries; i++) {
        if (*field_idx >= ctx->n_fields)
            goto too_many_fields;

        psabtf_struct_member_md_t md;
        if (psabtf_get_member_md_by_index(ctx->btf_metadata.btf, type_id, i, &md) != NO_ERROR) {
            fprintf(stderr, "invalid field or type\n");
            return 0;
        }

        ctx->fields[*field_idx].type = DIGEST_FIELD_TYPE_DATA;
        ctx->fields[*field_idx].data_offset = base_offset + md.bit_offset / 8;
        ctx->fields[*field_idx].data_len = psabtf_get_type_size_by_id(ctx->btf_metadata.btf, md.effective_type_id);
        const char *field_name = btf__name_by_offset(ctx->btf_metadata.btf, md.member->name_off);
        if (field_name != NULL) {
            ctx->fields[*field_idx].name = strdup(field_name);
            if (ctx->fields[*field_idx].name == NULL) {
                fprintf(stderr, "not enough memory\n");
                return ENOMEM;
            }
        }

        const struct btf_type *member_type = psabtf_get_type_by_id(ctx->btf_metadata.btf, md.effective_type_id);
        if (btf_is_struct(member_type)) {
            ctx->fields[*field_idx].type = DIGEST_FIELD_TYPE_STRUCT_START;
            (*field_idx)++;
            if (*field_idx >= ctx->n_fields)
                goto too_many_fields;
            int ret = parse_digest_struct(ctx, md.effective_type_id, field_idx, base_offset + md.bit_offset / 8);
            if (ret != NO_ERROR)
                return ret;

            if (*field_idx >= ctx->n_fields)
                goto too_many_fields;
            /* field_idx should point outside the last inserted entry, now add marker for struct end */
            ctx->fields[*field_idx].type = DIGEST_FIELD_TYPE_STRUCT_END;
        }

        (*field_idx)++;
    }

    return NO_ERROR;

too_many_fields:
    fprintf(stderr, "to many fields\n");
    return EFBIG;
}

static int parse_digest_btf(psabpf_digest_context_t *ctx)
{
    uint32_t type_id = psabtf_get_member_type_id_by_name(ctx->btf_metadata.btf, ctx->queue.btf_type_id, "value");

    if (type_id == 0) {
        fprintf(stderr, "warning: BTF type not found for digest, placing all the data in a single field\n");
        return setup_context_no_btf(ctx);
    }

    ctx->n_fields = count_total_fields(ctx, type_id);
    ctx->fields = calloc(ctx->n_fields, sizeof(psabpf_digest_field_descriptor_t));
    if (ctx->n_fields == 0 || ctx->fields == NULL) {
        fprintf(stderr, "failed to count fields\n");
        return EINVAL;
    }

    unsigned field_idx = 0;

    return parse_digest_struct(ctx, type_id, &field_idx, 0);
}

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

    ret = parse_digest_btf(ctx);
    if (ret != NO_ERROR) {
        fprintf(stderr, "failed to obtain fields names\n");
        return ret;
    }

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
    if (ctx == NULL || digest == NULL)
        return NULL;

    if (digest->current_field_id >= ctx->n_fields) {
        digest->current_field_id = 0;
        return NULL;
    }

    if (ctx->fields[digest->current_field_id].type == DIGEST_FIELD_TYPE_UNKNOWN)
        return NULL;

    digest->current.type = ctx->fields[digest->current_field_id].type;
    digest->current.data_len = ctx->fields[digest->current_field_id].data_len;
    digest->current.name = ctx->fields[digest->current_field_id].name;
    digest->current.data = digest->raw_data + ctx->fields[digest->current_field_id].data_offset;

    digest->current_field_id = digest->current_field_id + 1;

    return &digest->current;
}

psabpf_digest_field_type_t psabpf_digest_get_field_type(psabpf_digest_field_t *field)
{
    return field->type;
}

const char * psabpf_digest_get_field_name(psabpf_digest_field_t *field)
{
    return field->name;
}

const void * psabpf_digest_get_field_data(psabpf_digest_field_t *field)
{
    return field->data;
}

size_t psabpf_digest_get_field_data_len(psabpf_digest_field_t *field)
{
    return field->data_len;
}
