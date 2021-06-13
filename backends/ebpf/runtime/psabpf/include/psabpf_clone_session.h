#include "psabpf.h"

#define PSABPF_MAX_CLONE_SESSION_MEMBERS 64

/**
 * The name of the BPF MAP storing clone sessions.
 */
static const char *CLONE_SESSION_TABLE = "clone_session_tbl";

/*
 * PRE - Clone Sessions
 */
typedef uint32_t psabpf_clone_session_id_t;
struct psabpf_clone_session_entry {
    uint32_t  egress_port;
    uint16_t  instance;
    uint8_t   class_of_service;
    uint8_t   truncate;
    uint16_t  packet_length_bytes;
} __attribute__((aligned(4)));

typedef struct psabpf_clone_session_entry psabpf_clone_session_entry_t;

typedef struct psabpf_clone_session_ctx {
    psabpf_clone_session_id_t id;

    // TODO: to consider if this is the best way to iterate
    size_t curr_idx;
    psabpf_clone_session_entry_t *next_id;
} psabpf_clone_session_ctx_t;


void psabpf_clone_session_context_init(psabpf_clone_session_ctx_t *ctx);
void psabpf_clone_session_context_free(psabpf_clone_session_ctx_t *ctx);

void psabpf_clone_session_id(psabpf_clone_session_ctx_t *ctx, psabpf_clone_session_id_t id);

// TODO: add function to get all identifiers of clone sessions, which are created.
int psabpf_clone_session_create(psabpf_context_t *ctx, psabpf_clone_session_ctx_t *session);
int psabpf_clone_session_exists(psabpf_context_t *ctx, psabpf_clone_session_ctx_t *session);
int psabpf_clone_session_delete(psabpf_context_t *ctx, psabpf_clone_session_ctx_t *session);

void psabpf_clone_session_entry_init(psabpf_clone_session_entry_t *entry);
void psabpf_clone_session_entry_free(psabpf_clone_session_entry_t *entry);

void psabpf_clone_session_entry_port(psabpf_clone_session_entry_t *entry, uint32_t egress_port);
void psabpf_clone_session_entry_instance(psabpf_clone_session_entry_t *entry, uint16_t instance);
void psabpf_clone_session_entry_cos(psabpf_clone_session_entry_t *entry, uint8_t class_of_service);
int psabpf_clone_session_entry_truncate_enable(psabpf_clone_session_entry_t *entry, uint16_t packet_length_bytes);
// The function to set 'truncate' to false.
int psabpf_clone_session_entry_truncate_disable(psabpf_clone_session_entry_t *entry);

int psabpf_clone_session_entry_update(psabpf_context_t *ctx, psabpf_clone_session_ctx_t *session, psabpf_clone_session_entry_t *entry);
int psabpf_clone_session_entry_delete(psabpf_context_t *ctx, psabpf_clone_session_ctx_t *session, psabpf_clone_session_entry_t *entry);
int psabpf_clone_session_entry_exists(psabpf_context_t *ctx, psabpf_clone_session_ctx_t *session, psabpf_clone_session_entry_t *entry);
int psabpf_clone_session_entry_get(psabpf_context_t *ctx, psabpf_clone_session_ctx_t *session, psabpf_clone_session_entry_t *entry);

/*
 * Example:
 * psabpf_clone_session_ctx_t ctx;
 * psabpf_clone_session_context_init(&ctx);
 *
 * psabpf_clone_session_entry_t entry;
 * psabpf_clone_session_entry_init(&entry);
 *
 * while(psabpf_clone_session_entry_getnext(&ctx, &entry)) {
 *     // print entry fields
 * }
 *
 * psabpf_clone_session_entry_free(&entry);
 * psabpf_clone_session_context_free(&ctx);
 *
 */
int psabpf_clone_session_entry_getnext(psabpf_clone_session_ctx_t *ctx, psabpf_clone_session_entry_t **entry);
