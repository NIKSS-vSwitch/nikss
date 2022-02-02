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
void psabpf_clone_session_entry_truncate_enable(psabpf_clone_session_entry_t *entry, uint16_t packet_length_bytes);
// The function to set 'truncate' to false.
void psabpf_clone_session_entry_truncate_disable(psabpf_clone_session_entry_t *entry);

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
