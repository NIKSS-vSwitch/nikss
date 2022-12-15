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

#ifndef __NIKSS_H
#define __NIKSS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NO_ERROR 0

/*
 * Internal types
 */

typedef struct nikss_btf {
    void * btf;
    /* To create bpf maps with BTF info */
    int btf_fd;
} nikss_btf_t;

typedef struct nikss_bpf_map_descriptor {
    int fd;
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    /* Effective type IDs for key/value */
    uint32_t key_type_id;
    uint32_t value_type_id;
    /* Type IDs used by map definition for key/value */
    uint32_t map_key_type_id;
    uint32_t map_value_type_id;
} nikss_bpf_map_descriptor_t;

/*
 * General purpose types and functions
 */

typedef uint32_t nikss_pipeline_id_t;

/**
 * \brief          Global NIKSS context. Should be maintained between calls to the NIKSS API.
 */
typedef struct nikss_context {
    nikss_pipeline_id_t pipeline_id;
} nikss_context_t;

/**
 * Initialize the NIKSS context.
 *
 * @param ctx
 */
void nikss_context_init(nikss_context_t *ctx);

/**
 * Clear the NIKSS context.
 *
 * @param ctx
 */
void nikss_context_free(nikss_context_t *ctx);

/**
 * The NIKSS context is pipeline-scoped.
 * This functions allow to set/get pipeline object to control.
 */
void nikss_context_set_pipeline(nikss_context_t *ctx, nikss_pipeline_id_t pipeline_id);
nikss_pipeline_id_t nikss_context_get_pipeline(nikss_context_t *ctx);

typedef enum nikss_struct_field_type {
    NIKSS_STRUCT_FIELD_TYPE_UNKNOWN = 0,
    NIKSS_STRUCT_FIELD_TYPE_DATA,
    /* For nested structures */
    NIKSS_STRUCT_FIELD_TYPE_STRUCT_START,
    NIKSS_STRUCT_FIELD_TYPE_STRUCT_END
} nikss_struct_field_type_t;

/* Type for internal use */
typedef struct nikss_struct_field_descriptor {
    nikss_struct_field_type_t type;
    size_t data_offset;
    size_t data_len;
    const char *name;
} nikss_struct_field_descriptor_t;

typedef struct nikss_struct_field_descriptor_set {
    size_t n_fields;
    nikss_struct_field_descriptor_t *fields;
    bool decoded_with_btf;
} nikss_struct_field_descriptor_set_t;

/* Used to read/write structures */
typedef struct nikss_struct_field {
    nikss_struct_field_type_t type;
    void *data;
    size_t data_len;
    const char *name;
} nikss_struct_field_t;

typedef struct nikss_struct_field_set {
    size_t n_fields;
    nikss_struct_field_t *fields;
} nikss_struct_field_set_t;

nikss_struct_field_type_t nikss_struct_get_field_type(nikss_struct_field_t *field);
const char * nikss_struct_get_field_name(nikss_struct_field_t *field);
const void * nikss_struct_get_field_data(nikss_struct_field_t *field);
size_t nikss_struct_get_field_data_len(nikss_struct_field_t *field);

/*
 * Counters
 */

typedef uint64_t nikss_counter_value_t;

typedef enum nikss_counter_type {
    NIKSS_COUNTER_TYPE_UNKNOWN = 0,
    NIKSS_COUNTER_TYPE_BYTES,
    NIKSS_COUNTER_TYPE_PACKETS,
    NIKSS_COUNTER_TYPE_BYTES_AND_PACKETS,
} nikss_counter_type_t;

typedef struct nikss_counter_entry {
    nikss_struct_field_set_t entry_key;
    char *raw_key;
    size_t current_key_id;
    nikss_struct_field_t current_field;

    nikss_counter_value_t bytes;
    nikss_counter_value_t packets;
} nikss_counter_entry_t;

typedef struct nikss_counter_context {
    nikss_bpf_map_descriptor_t counter;
    nikss_counter_type_t counter_type;

    nikss_btf_t btf_metadata;
    nikss_struct_field_descriptor_set_t key_fds;

    nikss_counter_entry_t current_entry;
    void *prev_entry_key;
} nikss_counter_context_t;

void nikss_counter_ctx_init(nikss_counter_context_t *ctx);
void nikss_counter_ctx_free(nikss_counter_context_t *ctx);
int nikss_counter_ctx_name(nikss_context_t *nikss_ctx, nikss_counter_context_t *ctx, const char *name);

void nikss_counter_entry_init(nikss_counter_entry_t *entry);
void nikss_counter_entry_free(nikss_counter_entry_t *entry);

/* Can be called multiple times. */
int nikss_counter_entry_set_key(nikss_counter_entry_t *entry, const void *data, size_t data_len);
/* Valid after call to nikss_counter_get() or nikss_counter_get_next(). */
nikss_struct_field_t *nikss_counter_entry_get_next_key(nikss_counter_context_t *ctx, nikss_counter_entry_t *entry);

nikss_counter_type_t nikss_counter_get_type(nikss_counter_context_t *ctx);
void nikss_counter_entry_set_packets(nikss_counter_entry_t *entry, nikss_counter_value_t packets);
void nikss_counter_entry_set_bytes(nikss_counter_entry_t *entry, nikss_counter_value_t bytes);
nikss_counter_value_t nikss_counter_entry_get_packets(nikss_counter_entry_t *entry);
nikss_counter_value_t nikss_counter_entry_get_bytes(nikss_counter_entry_t *entry);

int nikss_counter_get(nikss_counter_context_t *ctx, nikss_counter_entry_t *entry);
nikss_counter_entry_t *nikss_counter_get_next(nikss_counter_context_t *ctx);
int nikss_counter_set(nikss_counter_context_t *ctx, nikss_counter_entry_t *entry);
int nikss_counter_reset(nikss_counter_context_t *ctx, nikss_counter_entry_t *entry);

/*
 * P4 Registers
 */

typedef struct nikss_register_entry {
    nikss_struct_field_set_t entry_key;
    nikss_struct_field_set_t entry_value;
    char *raw_key;
    char *raw_value;
    size_t current_field_id;
    nikss_struct_field_t current_field;
} nikss_register_entry_t;

typedef struct nikss_register_context {
    nikss_bpf_map_descriptor_t reg;
    nikss_btf_t btf_metadata;
    nikss_struct_field_descriptor_set_t key_fds;
    nikss_struct_field_descriptor_set_t value_fds;
    nikss_register_entry_t current_entry;
    void *prev_entry_key;
} nikss_register_context_t;

void nikss_register_ctx_init(nikss_register_context_t *ctx);
void nikss_register_ctx_free(nikss_register_context_t *ctx);
int nikss_register_ctx_name(nikss_context_t *nikss_ctx, nikss_register_context_t *ctx, const char *name);

void nikss_register_entry_init(nikss_register_entry_t *entry);
void nikss_register_entry_free(nikss_register_entry_t *entry);
nikss_register_entry_t * nikss_register_get_next(nikss_register_context_t *ctx);

int nikss_register_entry_set_key(nikss_register_entry_t *entry, const void *data, size_t data_len);
int nikss_register_entry_set_value(nikss_register_entry_t *entry, const void *data, size_t data_len);
nikss_struct_field_t * nikss_register_get_next_index_field(nikss_register_context_t *ctx, nikss_register_entry_t *entry);
nikss_struct_field_t * nikss_register_get_next_value_field(nikss_register_context_t *ctx, nikss_register_entry_t *entry);

int nikss_register_get(nikss_register_context_t *ctx, nikss_register_entry_t *entry);
int nikss_register_set(nikss_register_context_t *ctx, nikss_register_entry_t *entry);

/*
 * P4 Meters
 */

typedef uint64_t nikss_meter_value_t;

typedef struct nikss_meter_entry {
    nikss_struct_field_set_t index_sfs;
    char *raw_index;
    size_t current_index_field_id;
    nikss_struct_field_t current_index_field;

    nikss_meter_value_t pbs;
    nikss_meter_value_t pir;
    nikss_meter_value_t cbs;
    nikss_meter_value_t cir;
} nikss_meter_entry_t;

typedef struct nikss_meter_ctx {
    nikss_btf_t btf_metadata;
    nikss_bpf_map_descriptor_t meter;
    nikss_struct_field_descriptor_set_t index_fds;

    nikss_meter_entry_t current_entry;
    void *previous_index;
} nikss_meter_ctx_t;

void nikss_meter_entry_init(nikss_meter_entry_t *entry);
void nikss_meter_entry_free(nikss_meter_entry_t *entry);
int nikss_meter_entry_index(nikss_meter_entry_t *entry, const char *data, size_t size);
int nikss_meter_entry_data(nikss_meter_entry_t *entry,
                           nikss_meter_value_t pir,
                           nikss_meter_value_t pbs,
                           nikss_meter_value_t cir,
                           nikss_meter_value_t cbs);

int nikss_meter_entry_get_data(nikss_meter_entry_t *entry,
                               nikss_meter_value_t *pir,
                               nikss_meter_value_t *pbs,
                               nikss_meter_value_t *cir,
                               nikss_meter_value_t *cbs);
nikss_struct_field_t * nikss_meter_entry_get_next_index_field(nikss_meter_ctx_t *ctx, nikss_meter_entry_t *entry);

void nikss_meter_ctx_init(nikss_meter_ctx_t *ctx);
void nikss_meter_ctx_free(nikss_meter_ctx_t *ctx);
int nikss_meter_ctx_name(nikss_meter_ctx_t *ctx, nikss_context_t *nikss_ctx, const char *name);
int nikss_meter_entry_get(nikss_meter_ctx_t *ctx, nikss_meter_entry_t *entry);
nikss_meter_entry_t *nikss_meter_get_next(nikss_meter_ctx_t *ctx);
int nikss_meter_entry_update(nikss_meter_ctx_t *ctx, nikss_meter_entry_t *entry);
/* When entry is null or nikss_meter_entry_index() has not been executed before
 * on meter entry then resets all entries in meter. */
int nikss_meter_entry_reset(nikss_meter_ctx_t *ctx, nikss_meter_entry_t *entry);

/*
 * Tables
 */

enum nikss_matchkind_t {
    NIKSS_EXACT,
    NIKSS_LPM,
    NIKSS_TERNARY,
    NIKSS_RANGE
};

// TODO: this struct may not be well-designed yet; we need feedback from implementation; to be adjusted
typedef struct nikss_match_key {
    enum nikss_matchkind_t type;
    void *data;
    size_t key_size;
    union {
        struct {
            // used only for 'ternary'
            void *mask;
            size_t mask_size;
        } ternary;
        struct {
            // used only for 'lpm'
            size_t prefix_len;
        } lpm;
        struct {
            // used only for 'range'
            const uint64_t start;
            const uint64_t end;
        } range;
    } u;

    /* Used to tell whether allocated memory for this nikss_match_key_t instance
     * can be freed or not. If true then this allocated memory can be freed. Otherwise, not.
     * In some cases weak copy of instance is returned to client of this API.
     * For a such weak copy new memory is not allocated, only address of area of
     * memory from original instance is copied. In these weak copies field mem_can_be_freed
     * is set to false and memory is not deallocated. Memory will be freed when
     * freeing original object. */
    bool mem_can_be_freed;
} nikss_match_key_t;

typedef struct nikss_action_param {
    char *data;  /* might be an action data or reference */
    size_t len;
    bool is_group_reference;
    /* Used to tell whether allocated memory for this nikss_match_key_t instance
     * can be freed or not. If true then this allocated memory can be freed. Otherwise, not.
     * In some cases weak copy of instance is returned to client of this API.
     * For a such weak copy new memory is not allocated, only address of area of
     * memory from original instance is copied. In these weak copies field mem_can_be_freed
     * is set to false and memory is not deallocated. Memory will be freed when
     * freeing original object. */
    bool mem_can_be_freed;
    uint32_t param_id;
} nikss_action_param_t;

typedef struct nikss_action {
    uint32_t action_id;

    size_t n_params;
    nikss_action_param_t *params;
} nikss_action_t;

typedef struct nikss_direct_counter_entry {
    nikss_counter_entry_t counter;
    unsigned counter_idx;
} nikss_direct_counter_entry_t;

typedef struct nikss_direct_counter_context {
    const char *name;
    nikss_counter_type_t counter_type;
    size_t counter_size;
    size_t counter_offset;
    unsigned counter_idx;
    /* Used to tell whether allocated memory for this nikss_match_key_t instance
     * can be freed or not. If true then this allocated memory can be freed. Otherwise, not.
     * In some cases weak copy of instance is returned to client of this API.
     * For a such weak copy new memory is not allocated, only address of area of
     * memory from original instance is copied. In these weak copies field mem_can_be_freed
     * is set to false and memory is not deallocated. Memory will be freed when
     * freeing original object. */
    bool mem_can_be_freed;
} nikss_direct_counter_context_t;

typedef struct nikss_direct_meter_entry {
    nikss_meter_entry_t meter;
    unsigned meter_idx;
} nikss_direct_meter_entry_t;

typedef struct nikss_direct_meter_context {
    const char *name;
    size_t meter_size;
    size_t meter_offset;
    unsigned meter_idx;
    /* Used to tell whether allocated memory for this nikss_match_key_t instance
     * can be freed or not. If true then this allocated memory can be freed. Otherwise, not.
     * In some cases weak copy of instance is returned to client of this API.
     * For a such weak copy new memory is not allocated, only address of area of
     * memory from original instance is copied. In these weak copies field mem_can_be_freed
     * is set to false and memory is not deallocated. Memory will be freed when
     * freeing original object. */
    bool mem_can_be_freed;
} nikss_direct_meter_context_t;

typedef struct nikss_table_entry {
    size_t n_keys;
    nikss_match_key_t **match_keys;

    nikss_action_t *action;

    uint32_t priority;

    size_t n_direct_counters;
    nikss_direct_counter_entry_t *direct_counters;

    size_t n_direct_meters;
    nikss_direct_meter_entry_t *direct_meters;

    /* For iteration over entry data */
    size_t current_match_key_id;
    nikss_match_key_t current_match_key;
    size_t current_action_param_id;
    nikss_action_param_t current_action_param;
    size_t current_direct_counter_ctx_id;
    nikss_direct_counter_context_t current_direct_counter_ctx;
    size_t current_direct_meter_ctx_id;
    nikss_direct_meter_context_t current_direct_meter_ctx;
} nikss_table_entry_t;

/*
 * TODO: specific fields of table entry context are still to be added.
 * The table entry context may store information about a table itself (e.g. key size, num of entries, etc.).
 * It may be filled in based on the P4Info file.
 */
typedef struct nikss_table_entry_context {
    nikss_bpf_map_descriptor_t table;
    nikss_bpf_map_descriptor_t default_entry;
    bool is_indirect;
    bool is_ternary;

    /* for ternary tables */
    nikss_bpf_map_descriptor_t prefixes;
    nikss_bpf_map_descriptor_t tuple_map;

    /* for cache maintenance */
    nikss_bpf_map_descriptor_t cache;

    nikss_btf_t btf_metadata;

    /* DirectCounter */
    size_t n_direct_counters;
    nikss_direct_counter_context_t *direct_counters_ctx;

    /* DirectMeter */
    size_t n_direct_meters;
    nikss_direct_meter_context_t *direct_meters_ctx;

    /* ActionSelector and ActionProfile
     * TODO: use this to construct value*/
    nikss_struct_field_descriptor_set_t table_implementations;
    nikss_struct_field_descriptor_set_t table_implementation_group_marks;

    /* for iteration over table */
    void *current_raw_key;
    void *current_raw_key_mask;
    nikss_table_entry_t current_entry;
} nikss_table_entry_ctx_t;

void nikss_table_entry_ctx_init(nikss_table_entry_ctx_t *ctx);
void nikss_table_entry_ctx_free(nikss_table_entry_ctx_t *ctx);
int nikss_table_entry_ctx_tblname(nikss_context_t *nikss_ctx, nikss_table_entry_ctx_t *ctx, const char *name);
void nikss_table_entry_ctx_mark_indirect(nikss_table_entry_ctx_t *ctx);
bool nikss_table_entry_ctx_is_indirect(nikss_table_entry_ctx_t *ctx);
bool nikss_table_entry_ctx_has_priority(nikss_table_entry_ctx_t *ctx);

void nikss_table_entry_init(nikss_table_entry_t *entry);
void nikss_table_entry_free(nikss_table_entry_t *entry);

/* can be invoked multiple times */
int nikss_table_entry_matchkey(nikss_table_entry_t *entry, nikss_match_key_t *mk);
nikss_match_key_t *nikss_table_entry_get_next_matchkey(nikss_table_entry_t *entry);

void nikss_table_entry_action(nikss_table_entry_t *entry, nikss_action_t *act);
/* only for ternary */
void nikss_table_entry_priority(nikss_table_entry_t *entry, uint32_t priority);
uint32_t nikss_table_entry_get_priority(nikss_table_entry_t *entry);

void nikss_matchkey_init(nikss_match_key_t *mk);
void nikss_matchkey_free(nikss_match_key_t *mk);
void nikss_matchkey_type(nikss_match_key_t *mk, enum nikss_matchkind_t type);
int nikss_matchkey_data(nikss_match_key_t *mk, const char *data, size_t size);
enum nikss_matchkind_t nikss_matchkey_get_type(nikss_match_key_t *mk);
const void *nikss_matchkey_get_data(nikss_match_key_t *mk);
size_t nikss_matchkey_get_data_size(nikss_match_key_t *mk);

/* only for lpm */
int nikss_matchkey_prefix_len(nikss_match_key_t *mk, uint32_t prefix);
uint32_t nikss_matchkey_get_prefix_len(nikss_match_key_t *mk);

/* only for ternary */
int nikss_matchkey_mask(nikss_match_key_t *mk, const char *mask, size_t size);
const void *nikss_matchkey_get_mask(nikss_match_key_t *mk);
size_t nikss_matchkey_get_mask_size(nikss_match_key_t *mk);

/* only for 'range' match */
int nikss_matchkey_start(nikss_match_key_t *mk, uint64_t start);
int nikss_matchkey_end(nikss_match_key_t *mk, uint64_t end);

int nikss_action_param_create(nikss_action_param_t *param, const char *data, size_t size);
/* should be called when nikss_action_param() is not called after nikss_action_param_create() */
void nikss_action_param_free(nikss_action_param_t *param);

void nikss_action_param_mark_group_reference(nikss_action_param_t *param);
bool nikss_action_param_is_group_reference(nikss_action_param_t *param);

nikss_action_param_t *nikss_action_param_get_next(nikss_table_entry_t *entry);
void *nikss_action_param_get_data(nikss_action_param_t *param);
size_t nikss_action_param_get_data_len(nikss_action_param_t *param);
const char *nikss_action_param_get_name(nikss_table_entry_ctx_t *ctx, nikss_table_entry_t *entry, nikss_action_param_t *param);

void nikss_action_init(nikss_action_t *action);
void nikss_action_free(nikss_action_t *action);
void nikss_action_set_id(nikss_action_t *action, uint32_t action_id);
#define NIKSS_INVALID_ACTION_ID 0xFFFFFFFF
/* Returns action ID or NIKSS_INVALID_ACTION_ID on error */
uint32_t nikss_table_get_action_id_by_name(nikss_table_entry_ctx_t *ctx, const char *name);
int nikss_action_param(nikss_action_t *action, nikss_action_param_t *param);
uint32_t nikss_action_get_id(nikss_table_entry_t *entry);
const char *nikss_action_get_name(nikss_table_entry_ctx_t *ctx, uint32_t action_id);

int nikss_table_entry_add(nikss_table_entry_ctx_t *ctx, nikss_table_entry_t *entry);
int nikss_table_entry_update(nikss_table_entry_ctx_t *ctx, nikss_table_entry_t *entry);
int nikss_table_entry_del(nikss_table_entry_ctx_t *ctx, nikss_table_entry_t *entry);
int nikss_table_entry_get(nikss_table_entry_ctx_t *ctx, nikss_table_entry_t *entry);
nikss_table_entry_t *nikss_table_entry_get_next(nikss_table_entry_ctx_t *ctx);

int nikss_table_entry_set_default_entry(nikss_table_entry_ctx_t *ctx, nikss_table_entry_t *entry);
int nikss_table_entry_get_default_entry(nikss_table_entry_ctx_t *ctx, nikss_table_entry_t *entry);

/* DirectCounter */
void nikss_direct_counter_ctx_init(nikss_direct_counter_context_t *dc_ctx);
void nikss_direct_counter_ctx_free(nikss_direct_counter_context_t *dc_ctx);
int nikss_direct_counter_ctx_name(nikss_direct_counter_context_t *dc_ctx,
                                  nikss_table_entry_ctx_t *table_ctx, const char *dc_name);

int nikss_table_entry_set_direct_counter(nikss_table_entry_t *entry, nikss_direct_counter_context_t *dc_ctx,
                                         nikss_counter_entry_t *dc);
nikss_direct_counter_context_t *nikss_direct_counter_get_next_ctx(nikss_table_entry_ctx_t *ctx, nikss_table_entry_t *entry);
nikss_counter_type_t nikss_direct_counter_get_type(nikss_direct_counter_context_t *dc_ctx);
const char *nikss_direct_counter_get_name(nikss_direct_counter_context_t *dc_ctx);
int nikss_direct_counter_get_entry(nikss_direct_counter_context_t *dc_ctx, nikss_table_entry_t *entry, nikss_counter_entry_t *dc);

/* DirectMeter */
void nikss_direct_meter_ctx_init(nikss_direct_meter_context_t *dm_ctx);
void nikss_direct_meter_ctx_free(nikss_direct_meter_context_t *dm_ctx);
int nikss_direct_meter_ctx_name(nikss_direct_meter_context_t *dm_ctx,
                                nikss_table_entry_ctx_t *table_ctx, const char *dm_name);

int nikss_table_entry_set_direct_meter(nikss_table_entry_t *entry, nikss_direct_meter_context_t *dm_ctx,
                                       nikss_meter_entry_t *dm);
nikss_direct_meter_context_t *nikss_direct_meter_get_next_ctx(nikss_table_entry_ctx_t *ctx, nikss_table_entry_t *entry);
const char *nikss_direct_meter_get_name(nikss_direct_meter_context_t *dm_ctx);
int nikss_direct_meter_get_entry(nikss_direct_meter_context_t *dm_ctx, nikss_table_entry_t *entry, nikss_meter_entry_t *dm);

/*
 * Action Selector and Action Profile
 */

typedef struct nikss_action_selector_member_context {
    uint32_t member_ref;
    nikss_action_t action;
    nikss_action_param_t current_action_param;
    size_t current_action_param_id;
} nikss_action_selector_member_context_t;

typedef struct nikss_action_selector_group_context {
    uint32_t group_ref;
} nikss_action_selector_group_context_t;

typedef struct nikss_action_selector_context {
    nikss_btf_t btf;

    nikss_bpf_map_descriptor_t map_of_groups;
    nikss_bpf_map_descriptor_t group;
    nikss_bpf_map_descriptor_t map_of_members;
    nikss_bpf_map_descriptor_t empty_group_action;
    nikss_bpf_map_descriptor_t cache;

    /* For iteration */
    nikss_action_selector_group_context_t current_group;
    uint32_t current_group_id;
    nikss_action_selector_member_context_t current_member;
    uint32_t current_member_id; /* used to iterate over members of group and over all possible members */
} nikss_action_selector_context_t;

void nikss_action_selector_ctx_init(nikss_action_selector_context_t *ctx);
void nikss_action_selector_ctx_free(nikss_action_selector_context_t *ctx);
int nikss_action_selector_ctx_name(nikss_context_t *nikss_ctx, nikss_action_selector_context_t *ctx, const char *name);

void nikss_action_selector_member_init(nikss_action_selector_member_context_t *member);
void nikss_action_selector_member_free(nikss_action_selector_member_context_t *member);

void nikss_action_selector_group_init(nikss_action_selector_group_context_t *group);
void nikss_action_selector_group_free(nikss_action_selector_group_context_t *group);

bool nikss_action_selector_has_group_capability(nikss_action_selector_context_t *ctx);

/* Reuse table API */
int nikss_action_selector_member_action(nikss_action_selector_member_context_t *member, nikss_action_t *action);

#define NIKSS_ACTION_SELECTOR_INVALID_REFERENCE 0
uint32_t nikss_action_selector_get_member_reference(nikss_action_selector_member_context_t *member);
void nikss_action_selector_set_member_reference(nikss_action_selector_member_context_t *member, uint32_t member_ref);
uint32_t nikss_action_selector_get_group_reference(nikss_action_selector_group_context_t *group);
void nikss_action_selector_set_group_reference(nikss_action_selector_group_context_t *group, uint32_t group_ref);

int nikss_action_selector_add_member(nikss_action_selector_context_t *ctx, nikss_action_selector_member_context_t *member);
int nikss_action_selector_update_member(nikss_action_selector_context_t *ctx, nikss_action_selector_member_context_t *member);
int nikss_action_selector_del_member(nikss_action_selector_context_t *ctx, nikss_action_selector_member_context_t *member);

int nikss_action_selector_add_group(nikss_action_selector_context_t *ctx, nikss_action_selector_group_context_t *group);
int nikss_action_selector_del_group(nikss_action_selector_context_t *ctx, nikss_action_selector_group_context_t *group);

int nikss_action_selector_add_member_to_group(nikss_action_selector_context_t *ctx,
                                              nikss_action_selector_group_context_t *group,
                                              nikss_action_selector_member_context_t *member);
int nikss_action_selector_del_member_from_group(nikss_action_selector_context_t *ctx,
                                                nikss_action_selector_group_context_t *group,
                                                nikss_action_selector_member_context_t *member);

/* Reuse table API */
int nikss_action_selector_set_empty_group_action(nikss_action_selector_context_t *ctx, nikss_action_t *action);
int nikss_action_selector_get_empty_group_action(nikss_action_selector_context_t *ctx,
                                                 nikss_action_selector_member_context_t *member);
/* See nikss_table_get_action_id_by_name() */
uint32_t nikss_action_selector_get_action_id_by_name(nikss_action_selector_context_t *ctx, const char *name);

int nikss_action_selector_get_group(nikss_action_selector_context_t *ctx, nikss_action_selector_group_context_t *group);
nikss_action_selector_group_context_t *nikss_action_selector_get_next_group(nikss_action_selector_context_t *ctx);
nikss_action_selector_member_context_t *nikss_action_selector_get_next_group_member(nikss_action_selector_context_t *ctx,
                                                                                    nikss_action_selector_group_context_t *group);
nikss_action_selector_member_context_t *nikss_action_selector_get_next_member(nikss_action_selector_context_t *ctx);
int nikss_action_selector_get_member(nikss_action_selector_context_t *ctx, nikss_action_selector_member_context_t *member);

uint32_t nikss_action_selector_get_member_action_id(nikss_action_selector_context_t *ctx,
                                                    nikss_action_selector_member_context_t *member);
const char *nikss_action_selector_get_member_action_name(nikss_action_selector_context_t *ctx,
                                                         nikss_action_selector_member_context_t *member);
nikss_action_param_t *nikss_action_selector_action_param_get_next(nikss_action_selector_member_context_t *member);
const char *nikss_action_selector_action_param_get_name(nikss_action_selector_context_t *ctx,
                                                        nikss_action_selector_member_context_t *member,
                                                        nikss_action_param_t *param);

////// PacketIn / PacketOut
// TODO: to be implemented
//  - to listen on the specified PSA_PORT_CPU interfaces
//  - to send packet out of the specified PSA_PORT_CPU interface

////// MISC
// TODO: to be implemented
//  /* Use to retrieve report about packet processing from the data plane. */
//  int nikss_report_get_next();

#endif //__NIKSS_H
