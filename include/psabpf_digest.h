#ifndef __PSABPF_DIGEST_H
#define __PSABPF_DIGEST_H

#include <psabpf.h>

typedef struct psabpf_digest_context {
    psabpf_bpf_map_descriptor_t queue;
    psabpf_btf_t btf_metadata;

    uint32_t btf_type_id;
} psabpf_digest_context_t;

typedef enum psabpf_digest_field_type {
    DIGEST_FIELD_TYPE_DATA = 0,
    /* For nested structures */
    DIGEST_FIELD_TYPE_STRUCT_START,
    DIGEST_FIELD_TYPE_STRUCT_END
} psabpf_digest_field_type_t;

/* Used to iterate over fields of a single message */
typedef struct psabpf_digest_field {
    psabpf_digest_field_type_t type;
    void *data;
    size_t data_len;
    const char *name;

    /* used for tree-list like data structure */
    struct psabpf_digest_field *parent;
    struct psabpf_digest_field *children;
} psabpf_digest_field_t;

/* Used to read a next Digest message. */
typedef struct psabpf_digest {
    void *raw_data;  /* stores data from map as a single block */

    psabpf_digest_field_t *current;
    psabpf_digest_field_t tree;
} psabpf_digest_t;

void psabpf_digest_context_init(psabpf_digest_context_t *ctx);
void psabpf_digest_context_free(psabpf_digest_context_t *ctx);
int psabpf_digest_open(psabpf_context_t *psabpf_ctx, psabpf_digest_context_t *ctx, const char *name);
/* Will initialize digest, but must be later freed */
int psabpf_digest_get_next(psabpf_digest_context_t *ctx, psabpf_digest_t *digest);
void psabpf_digest_free(psabpf_digest_t *digest);

psabpf_digest_field_t * psabpf_digest_get_next_field(psabpf_digest_context_t *ctx, psabpf_digest_t *digest);
psabpf_digest_field_type_t psabpf_digest_get_field_type(psabpf_digest_field_t *field);
const char * psabpf_digest_get_field_name(psabpf_digest_field_t *field);
const void * psabpf_digest_get_field_data(psabpf_digest_field_t *field);
size_t psabpf_digest_get_field_data_len(psabpf_digest_field_t *field);

#endif  /* __PSABPF_DIGEST_H */
