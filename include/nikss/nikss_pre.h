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

#ifndef __NIKSS_PRE_H
#define __NIKSS_PRE_H

#include <nikss/nikss.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * PRE - Clone Sessions
 */
typedef uint32_t nikss_clone_session_id_t;

struct nikss_clone_session_entry {
    uint32_t  egress_port;
    uint16_t  instance;
    uint8_t   class_of_service;
    uint8_t   truncate;
    uint16_t  packet_length_bytes;
} __attribute__((aligned(4)));

typedef struct nikss_clone_session_entry nikss_clone_session_entry_t;

typedef struct nikss_clone_session_ctx {
    nikss_clone_session_id_t id;

    /* For iteration over entries in clone session */
    nikss_bpf_map_descriptor_t session_map;
    nikss_clone_session_entry_t current_entry;
    uint32_t current_egress_port;
    uint16_t current_instance;
} nikss_clone_session_ctx_t;


void nikss_clone_session_context_init(nikss_clone_session_ctx_t *ctx);
void nikss_clone_session_context_free(nikss_clone_session_ctx_t *ctx);

void nikss_clone_session_id(nikss_clone_session_ctx_t *ctx, nikss_clone_session_id_t id);
nikss_clone_session_id_t nikss_clone_session_get_id(nikss_clone_session_ctx_t *ctx);

int nikss_clone_session_create(nikss_context_t *ctx, nikss_clone_session_ctx_t *session);
bool nikss_clone_session_exists(nikss_context_t *ctx, nikss_clone_session_ctx_t *session);
int nikss_clone_session_delete(nikss_context_t *ctx, nikss_clone_session_ctx_t *session);

void nikss_clone_session_entry_init(nikss_clone_session_entry_t *entry);
void nikss_clone_session_entry_free(nikss_clone_session_entry_t *entry);

void nikss_clone_session_entry_port(nikss_clone_session_entry_t *entry, uint32_t egress_port);
uint32_t nikss_clone_session_entry_get_port(nikss_clone_session_entry_t *entry);
void nikss_clone_session_entry_instance(nikss_clone_session_entry_t *entry, uint16_t instance);
uint16_t nikss_clone_session_entry_get_instance(nikss_clone_session_entry_t *entry);
void nikss_clone_session_entry_cos(nikss_clone_session_entry_t *entry, uint8_t class_of_service);
uint8_t nikss_clone_session_entry_get_cos(nikss_clone_session_entry_t *entry);
void nikss_clone_session_entry_truncate_enable(nikss_clone_session_entry_t *entry, uint16_t packet_length_bytes);
void nikss_clone_session_entry_truncate_disable(nikss_clone_session_entry_t *entry);
bool nikss_clone_session_entry_get_truncate_state(nikss_clone_session_entry_t *entry);
uint16_t nikss_clone_session_entry_get_truncate_length(nikss_clone_session_entry_t *entry);

int nikss_clone_session_entry_update(nikss_context_t *ctx, nikss_clone_session_ctx_t *session, nikss_clone_session_entry_t *entry);
int nikss_clone_session_entry_delete(nikss_context_t *ctx, nikss_clone_session_ctx_t *session, nikss_clone_session_entry_t *entry);
int nikss_clone_session_entry_exists(nikss_context_t *ctx, nikss_clone_session_ctx_t *session, nikss_clone_session_entry_t *entry);
int nikss_clone_session_entry_get(nikss_context_t *ctx, nikss_clone_session_ctx_t *session, nikss_clone_session_entry_t *entry);

nikss_clone_session_entry_t *nikss_clone_session_get_next_entry(nikss_context_t *ctx, nikss_clone_session_ctx_t *session);

typedef struct nikss_clone_session_list {
    nikss_bpf_map_descriptor_t session_map;
    nikss_clone_session_id_t current_id;
    nikss_clone_session_ctx_t current_session;
} nikss_clone_session_list_t;

int nikss_clone_session_list_init(nikss_context_t *ctx, nikss_clone_session_list_t *list);
void nikss_clone_session_list_free(nikss_clone_session_list_t *list);
nikss_clone_session_ctx_t *nikss_clone_session_list_get_next_group(nikss_clone_session_list_t *list);

/*
 * PRE - Multicast Groups
 */
typedef uint32_t nikss_mcast_grp_id_t;

typedef struct nikss_mcast_grp_member {
    uint32_t egress_port;
    uint16_t instance;
} nikss_mcast_grp_member_t;

typedef struct nikss_mcast_grp_context {
    nikss_mcast_grp_id_t id;

    /* For iteration over members */
    nikss_bpf_map_descriptor_t group_map;
    nikss_mcast_grp_member_t current_member;
    uint32_t current_egress_port;
    uint16_t current_instance;
} nikss_mcast_grp_ctx_t;

void nikss_mcast_grp_context_init(nikss_mcast_grp_ctx_t *group);
void nikss_mcast_grp_context_free(nikss_mcast_grp_ctx_t *group);

void nikss_mcast_grp_id(nikss_mcast_grp_ctx_t *group, nikss_mcast_grp_id_t mcast_grp_id);
nikss_mcast_grp_id_t nikss_mcast_grp_get_id(nikss_mcast_grp_ctx_t *group);

int nikss_mcast_grp_create(nikss_context_t *ctx, nikss_mcast_grp_ctx_t *group);
bool nikss_mcast_grp_exists(nikss_context_t *ctx, nikss_mcast_grp_ctx_t *group);
int nikss_mcast_grp_delete(nikss_context_t *ctx, nikss_mcast_grp_ctx_t *group);

void nikss_mcast_grp_member_init(nikss_mcast_grp_member_t *member);
void nikss_mcast_grp_member_free(nikss_mcast_grp_member_t *member);

void nikss_mcast_grp_member_port(nikss_mcast_grp_member_t *member, uint32_t egress_port);
void nikss_mcast_grp_member_instance(nikss_mcast_grp_member_t *member, uint16_t instance);

uint32_t nikss_mcast_grp_member_get_port(nikss_mcast_grp_member_t *member);
uint16_t nikss_mcast_grp_member_get_instance(nikss_mcast_grp_member_t *member);

int nikss_mcast_grp_member_update(nikss_context_t *ctx, nikss_mcast_grp_ctx_t *group, nikss_mcast_grp_member_t *member);
int nikss_mcast_grp_member_exists(nikss_context_t *ctx, nikss_mcast_grp_ctx_t *group, nikss_mcast_grp_member_t *member);
int nikss_mcast_grp_member_delete(nikss_context_t *ctx, nikss_mcast_grp_ctx_t *group, nikss_mcast_grp_member_t *member);

nikss_mcast_grp_member_t *nikss_mcast_grp_get_next_member(nikss_context_t *ctx, nikss_mcast_grp_ctx_t *group);

typedef struct nikss_mcast_grp_list {
    nikss_bpf_map_descriptor_t group_map;
    nikss_mcast_grp_id_t current_id;
    nikss_mcast_grp_ctx_t current_group;
} nikss_mcast_grp_list_t;

int nikss_mcast_grp_list_init(nikss_context_t *ctx, nikss_mcast_grp_list_t *list);
void nikss_mcast_grp_list_free(nikss_mcast_grp_list_t *list);
nikss_mcast_grp_ctx_t *nikss_mcast_grp_list_get_next_group(nikss_mcast_grp_list_t *list);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif  /* __NIKSS_PRE_H */
