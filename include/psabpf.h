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

#ifndef __PSABPF_H
#define __PSABPF_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define NO_ERROR 0

/*
 * Internal types
 */

typedef struct psabpf_btf {
    /* BTF metadata are associated with eBPF program, eBPF map may do not own BTF */
    int associated_prog;
    void * btf;
} psabpf_btf_t;

typedef struct psabpf_bpf_map_descriptor {
    int fd;
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t btf_type_id;  // TODO: key type ID and value type ID
    uint32_t max_entries;
} psabpf_bpf_map_descriptor_t;

/*
 * General purpose types and functions
 */

typedef uint32_t psabpf_pipeline_id_t;

/**
 * \brief          Global PSABPF context. Should be maintained between calls to the PSABPF API.
 */
typedef struct psabpf_context {
    psabpf_pipeline_id_t pipeline_id;
} psabpf_context_t;

/**
 * Initialize the PSABPF context.
 *
 * @param ctx
 */
void psabpf_context_init(psabpf_context_t *ctx);

/**
 * Clear the PSABPF context.
 *
 * @param ctx
 */
void psabpf_context_free(psabpf_context_t *ctx);

/**
 * The PSABPF context is pipeline-scoped.
 * This functions allow to set/get pipeline object to control.
 */
void psabpf_context_set_pipeline(psabpf_context_t *ctx, psabpf_pipeline_id_t pipeline_id);
psabpf_pipeline_id_t psabpf_context_get_pipeline(psabpf_context_t *ctx);

typedef enum psabpf_struct_field_type {
    PSABPF_STRUCT_FIELD_TYPE_UNKNOWN = 0,
    PSABPF_STRUCT_FIELD_TYPE_DATA,
    /* For nested structures */
    PSABPF_STRUCT_FIELD_TYPE_STRUCT_START,
    PSABPF_STRUCT_FIELD_TYPE_STRUCT_END
} psabpf_struct_field_type_t;

/* Type for internal use */
typedef struct psabpf_struct_field_descriptor {
    psabpf_struct_field_type_t type;
    size_t data_offset;
    size_t data_len;
    const char *name;
} psabpf_struct_field_descriptor_t;

typedef struct psabpf_struct_field_descriptor_set {
    size_t n_fields;
    psabpf_struct_field_descriptor_t *fields;
} psabpf_struct_field_descriptor_set_t;

/* Used to read/write structures */
typedef struct psabpf_struct_field {
    psabpf_struct_field_type_t type;
    void *data;
    size_t data_len;
    const char *name;
} psabpf_struct_field_t;

typedef struct psabpf_struct_field_set {
    size_t n_fields;
    psabpf_struct_field_t *fields;
} psabpf_struct_field_set_t;

psabpf_struct_field_type_t psabpf_struct_get_field_type(psabpf_struct_field_t *field);
const char * psabpf_struct_get_field_name(psabpf_struct_field_t *field);
const void * psabpf_struct_get_field_data(psabpf_struct_field_t *field);
size_t psabpf_struct_get_field_data_len(psabpf_struct_field_t *field);

/*
 * Counters
 */

typedef uint64_t psabpf_counter_value_t;

typedef enum psabpf_counter_type {
    PSABPF_COUNTER_TYPE_UNKNOWN = 0,
    PSABPF_COUNTER_TYPE_BYTES,
    PSABPF_COUNTER_TYPE_PACKETS,
    PSABPF_COUNTER_TYPE_BYTES_AND_PACKETS,
} psabpf_counter_type_t;

typedef struct psabpf_counter_entry {
    psabpf_struct_field_set_t entry_key;
    void *raw_key;
    size_t current_key_id;
    psabpf_struct_field_t current_field;

    psabpf_counter_value_t bytes;
    psabpf_counter_value_t packets;
} psabpf_counter_entry_t;

typedef struct psabpf_counter_context {
    psabpf_bpf_map_descriptor_t counter;
    psabpf_counter_type_t counter_type;

    psabpf_btf_t btf_metadata;
    psabpf_struct_field_descriptor_set_t key_fds;

    psabpf_counter_entry_t current_entry;
    void *prev_entry_key;
} psabpf_counter_context_t;

void psabpf_counter_ctx_init(psabpf_counter_context_t *ctx);
void psabpf_counter_ctx_free(psabpf_counter_context_t *ctx);
int psabpf_counter_ctx_name(psabpf_context_t *psabpf_ctx, psabpf_counter_context_t *ctx, const char *name);

void psabpf_counter_entry_init(psabpf_counter_entry_t *entry);
void psabpf_counter_entry_free(psabpf_counter_entry_t *entry);

/* Can be called multiple times. */
int psabpf_counter_entry_set_key(psabpf_counter_entry_t *entry, const void *data, size_t data_len);
/* Valid after call to psabpf_counter_get() or psabpf_counter_get_next(). */
psabpf_struct_field_t *psabpf_counter_entry_get_next_key(psabpf_counter_context_t *ctx, psabpf_counter_entry_t *entry);

psabpf_counter_type_t psabpf_counter_get_type(psabpf_counter_context_t *ctx);
void psabpf_counter_entry_set_packets(psabpf_counter_entry_t *entry, psabpf_counter_value_t packets);
void psabpf_counter_entry_set_bytes(psabpf_counter_entry_t *entry, psabpf_counter_value_t bytes);
psabpf_counter_value_t psabpf_counter_entry_get_packets(psabpf_counter_entry_t *entry);
psabpf_counter_value_t psabpf_counter_entry_get_bytes(psabpf_counter_entry_t *entry);

int psabpf_counter_get(psabpf_counter_context_t *ctx, psabpf_counter_entry_t *entry);
psabpf_counter_entry_t *psabpf_counter_get_next(psabpf_counter_context_t *ctx);
int psabpf_counter_set(psabpf_counter_context_t *ctx, psabpf_counter_entry_t *entry);
int psabpf_counter_reset(psabpf_counter_context_t *ctx, psabpf_counter_entry_t *entry);

/*
 * P4 Registers
 */

typedef struct psabpf_register_entry {
    psabpf_struct_field_set_t entry_key;
    psabpf_struct_field_set_t entry_value;
    void *raw_key;
    void *raw_value;
    size_t current_field_id;
    psabpf_struct_field_t current_field;
} psabpf_register_entry_t;

typedef struct psabpf_register_context {
    psabpf_bpf_map_descriptor_t reg;
    psabpf_btf_t btf_metadata;
    psabpf_struct_field_descriptor_set_t key_fds;
    psabpf_struct_field_descriptor_set_t value_fds;
    psabpf_register_entry_t current_entry;
    void *prev_entry_key;
} psabpf_register_context_t;

void psabpf_register_ctx_init(psabpf_register_context_t *ctx);
void psabpf_register_ctx_free(psabpf_register_context_t *ctx);
int psabpf_register_ctx_name(psabpf_context_t *psabpf_ctx, psabpf_register_context_t *ctx, const char *name);

void psabpf_register_entry_init(psabpf_register_entry_t *entry);
void psabpf_register_entry_free(psabpf_register_entry_t *entry);
psabpf_register_entry_t * psabpf_register_get_next(psabpf_register_context_t *ctx);

int psabpf_register_entry_set_key(psabpf_register_entry_t *entry, const void *data, size_t data_len);
int psabpf_register_entry_set_value(psabpf_register_entry_t *entry, const void *data, size_t data_len);
psabpf_struct_field_t * psabpf_register_get_next_index_field(psabpf_register_context_t *ctx, psabpf_register_entry_t *entry);
psabpf_struct_field_t * psabpf_register_get_next_value_field(psabpf_register_context_t *ctx, psabpf_register_entry_t *entry);

int psabpf_register_get(psabpf_register_context_t *ctx, psabpf_register_entry_t *entry);
int psabpf_register_set(psabpf_register_context_t *ctx, psabpf_register_entry_t *entry);

/*
 * P4 Meters
 */

typedef uint64_t psabpf_meter_value_t;

typedef struct {
    psabpf_struct_field_set_t index_sfs;
    void *raw_index;
    size_t current_index_field_id;
    psabpf_struct_field_t current_index_field;

    psabpf_meter_value_t pbs;
    psabpf_meter_value_t pir;
    psabpf_meter_value_t cbs;
    psabpf_meter_value_t cir;
} psabpf_meter_entry_t;

typedef struct {
    psabpf_btf_t btf_metadata;
    psabpf_bpf_map_descriptor_t meter;
    psabpf_struct_field_descriptor_set_t index_fds;
} psabpf_meter_ctx_t;

void psabpf_meter_entry_init(psabpf_meter_entry_t *entry);
void psabpf_meter_entry_free(psabpf_meter_entry_t *entry);
int psabpf_meter_entry_index(psabpf_meter_entry_t *entry, const char *data, size_t size);
int psabpf_meter_entry_data(psabpf_meter_entry_t *entry,
                            psabpf_meter_value_t pir,
                            psabpf_meter_value_t pbs,
                            psabpf_meter_value_t cir,
                            psabpf_meter_value_t cbs);

int psabpf_meter_entry_get_data(psabpf_meter_entry_t *entry,
                                psabpf_meter_value_t *pir,
                                psabpf_meter_value_t *pbs,
                                psabpf_meter_value_t *cir,
                                psabpf_meter_value_t *cbs);
psabpf_struct_field_t * psabpf_meter_entry_get_next_index_field(psabpf_meter_ctx_t *ctx, psabpf_meter_entry_t *entry);

void psabpf_meter_ctx_init(psabpf_meter_ctx_t *ctx);
void psabpf_meter_ctx_free(psabpf_meter_ctx_t *ctx);
int psabpf_meter_ctx_name(psabpf_meter_ctx_t *ctx, psabpf_context_t *psabpf_ctx, const char *name);
int psabpf_meter_entry_get(psabpf_meter_ctx_t *ctx, psabpf_meter_entry_t *entry);
int psabpf_meter_entry_update(psabpf_meter_ctx_t *ctx, psabpf_meter_entry_t *entry);
int psabpf_meter_entry_reset(psabpf_meter_ctx_t *ctx, psabpf_meter_entry_t *entry);

/*
 * Tables
 */

enum psabpf_matchkind_t {
    PSABPF_EXACT,
    PSABPF_LPM,
    PSABPF_TERNARY,
    PSABPF_RANGE
};

// TODO: this struct may not be well-designed yet; we need feedback from implementation; to be adjusted
typedef struct psabpf_match_key {
    enum psabpf_matchkind_t type;
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

    /* Used to tell whether allocated memory for this psabpf_match_key_t instance
     * can be freed or not. If true then this allocated memory can be freed. Otherwise, not.
     * In some cases weak copy of instance is returned to client of this API.
     * For a such weak copy new memory is not allocated, only address of area of
     * memory from original instance is copied. In these weak copies field mem_can_be_freed
     * is set to false and memory is not deallocated. Memory will be freed when
     * freeing original object. */
    bool mem_can_be_freed;
} psabpf_match_key_t;

typedef struct psabpf_action_param {
    char *data;  /* might be an action data or reference */
    size_t len;
    bool is_group_reference;
    /* Used to tell whether allocated memory for this psabpf_match_key_t instance
     * can be freed or not. If true then this allocated memory can be freed. Otherwise, not.
     * In some cases weak copy of instance is returned to client of this API.
     * For a such weak copy new memory is not allocated, only address of area of
     * memory from original instance is copied. In these weak copies field mem_can_be_freed
     * is set to false and memory is not deallocated. Memory will be freed when
     * freeing original object. */
    bool mem_can_be_freed;
    uint32_t param_id;
} psabpf_action_param_t;

typedef struct psabpf_action {
    uint32_t action_id;

    size_t n_params;
    psabpf_action_param_t *params;
} psabpf_action_t;

typedef struct psabpf_direct_counter_entry {
    psabpf_counter_entry_t counter;
    unsigned counter_idx;
} psabpf_direct_counter_entry_t;

typedef struct psabpf_direct_counter_context {
    const char *name;
    psabpf_counter_type_t counter_type;
    size_t counter_size;
    size_t counter_offset;
    unsigned counter_idx;
    /* Used to tell whether allocated memory for this psabpf_match_key_t instance
     * can be freed or not. If true then this allocated memory can be freed. Otherwise, not.
     * In some cases weak copy of instance is returned to client of this API.
     * For a such weak copy new memory is not allocated, only address of area of
     * memory from original instance is copied. In these weak copies field mem_can_be_freed
     * is set to false and memory is not deallocated. Memory will be freed when
     * freeing original object. */
    bool mem_can_be_freed;
} psabpf_direct_counter_context_t;

typedef struct psabpf_direct_meter_entry {
    psabpf_meter_entry_t meter;
    unsigned meter_idx;
} psabpf_direct_meter_entry_t;

typedef struct psabpf_direct_meter_context {
    const char *name;
    size_t meter_size;
    size_t meter_offset;
    unsigned meter_idx;
    /* Used to tell whether allocated memory for this psabpf_match_key_t instance
     * can be freed or not. If true then this allocated memory can be freed. Otherwise, not.
     * In some cases weak copy of instance is returned to client of this API.
     * For a such weak copy new memory is not allocated, only address of area of
     * memory from original instance is copied. In these weak copies field mem_can_be_freed
     * is set to false and memory is not deallocated. Memory will be freed when
     * freeing original object. */
    bool mem_can_be_freed;
} psabpf_direct_meter_context_t;

typedef struct psabpf_table_entry {
    size_t n_keys;
    psabpf_match_key_t **match_keys;

    psabpf_action_t *action;

    uint32_t priority;

    size_t n_direct_counters;
    psabpf_direct_counter_entry_t *direct_counters;

    size_t n_direct_meters;
    psabpf_direct_meter_entry_t *direct_meters;

    /* For iteration over entry data */
    size_t current_match_key_id;
    psabpf_match_key_t current_match_key;
    size_t current_action_param_id;
    psabpf_action_param_t current_action_param;
    size_t current_direct_counter_ctx_id;
    psabpf_direct_counter_context_t current_direct_counter_ctx;
    size_t current_direct_meter_ctx_id;
    psabpf_direct_meter_context_t current_direct_meter_ctx;
} psabpf_table_entry_t;

/*
 * TODO: specific fields of table entry context are still to be added.
 * The table entry context may store information about a table itself (e.g. key size, num of entries, etc.).
 * It may be filled in based on the P4Info file.
 */
typedef struct psabpf_table_entry_context {
    psabpf_bpf_map_descriptor_t table;
    psabpf_bpf_map_descriptor_t default_entry;
    bool is_indirect;
    bool is_ternary;

    /* for ternary tables */
    psabpf_bpf_map_descriptor_t prefixes;
    psabpf_bpf_map_descriptor_t tuple_map;

    /* for cache maintenance */
    psabpf_bpf_map_descriptor_t cache;

    psabpf_btf_t btf_metadata;

    /* DirectCounter */
    size_t n_direct_counters;
    psabpf_direct_counter_context_t *direct_counters_ctx;

    /* DirectMeter */
    size_t n_direct_meters;
    psabpf_direct_meter_context_t *direct_meters_ctx;

    /* ActionSelector and ActionProfile
     * TODO: use this to construct value*/
    psabpf_struct_field_descriptor_set_t table_implementations;
    psabpf_struct_field_descriptor_set_t table_implementation_group_marks;

    /* for iteration over table */
    void *current_raw_key;
    void *current_raw_key_mask;
    psabpf_table_entry_t current_entry;
} psabpf_table_entry_ctx_t;

void psabpf_table_entry_ctx_init(psabpf_table_entry_ctx_t *ctx);
void psabpf_table_entry_ctx_free(psabpf_table_entry_ctx_t *ctx);
int psabpf_table_entry_ctx_tblname(psabpf_context_t *psabpf_ctx, psabpf_table_entry_ctx_t *ctx, const char *name);
void psabpf_table_entry_ctx_mark_indirect(psabpf_table_entry_ctx_t *ctx);
bool psabpf_table_entry_ctx_is_indirect(psabpf_table_entry_ctx_t *ctx);
bool psabpf_table_entry_ctx_has_priority(psabpf_table_entry_ctx_t *ctx);

void psabpf_table_entry_init(psabpf_table_entry_t *entry);
void psabpf_table_entry_free(psabpf_table_entry_t *entry);

/* can be invoked multiple times */
int psabpf_table_entry_matchkey(psabpf_table_entry_t *entry, psabpf_match_key_t *mk);
psabpf_match_key_t *psabpf_table_entry_get_next_matchkey(psabpf_table_entry_t *entry);

void psabpf_table_entry_action(psabpf_table_entry_t *entry, psabpf_action_t *act);
/* only for ternary */
void psabpf_table_entry_priority(psabpf_table_entry_t *entry, uint32_t priority);
uint32_t psabpf_table_entry_get_priority(psabpf_table_entry_t *entry);

void psabpf_matchkey_init(psabpf_match_key_t *mk);
void psabpf_matchkey_free(psabpf_match_key_t *mk);
void psabpf_matchkey_type(psabpf_match_key_t *mk, enum psabpf_matchkind_t type);
int psabpf_matchkey_data(psabpf_match_key_t *mk, const char *data, size_t size);
enum psabpf_matchkind_t psabpf_matchkey_get_type(psabpf_match_key_t *mk);
const void *psabpf_matchkey_get_data(psabpf_match_key_t *mk);
size_t psabpf_matchkey_get_data_size(psabpf_match_key_t *mk);

/* only for lpm */
int psabpf_matchkey_prefix_len(psabpf_match_key_t *mk, uint32_t prefix);
uint32_t psabpf_matchkey_get_prefix_len(psabpf_match_key_t *mk);

/* only for ternary */
int psabpf_matchkey_mask(psabpf_match_key_t *mk, const char *mask, size_t size);
const void *psabpf_matchkey_get_mask(psabpf_match_key_t *mk);
size_t psabpf_matchkey_get_mask_size(psabpf_match_key_t *mk);

/* only for 'range' match */
int psabpf_matchkey_start(psabpf_match_key_t *mk, uint64_t start);
int psabpf_matchkey_end(psabpf_match_key_t *mk, uint64_t end);

int psabpf_action_param_create(psabpf_action_param_t *param, const char *data, size_t size);
/* should be called when psabpf_action_param() is not called after psabpf_action_param_create() */
void psabpf_action_param_free(psabpf_action_param_t *param);

void psabpf_action_param_mark_group_reference(psabpf_action_param_t *param);
bool psabpf_action_param_is_group_reference(psabpf_action_param_t *param);

psabpf_action_param_t *psabpf_action_param_get_next(psabpf_table_entry_t *entry);
void *psabpf_action_param_get_data(psabpf_action_param_t *param);
size_t psabpf_action_param_get_data_len(psabpf_action_param_t *param);
const char *psabpf_action_param_get_name(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry, psabpf_action_param_t *param);

void psabpf_action_init(psabpf_action_t *action);
void psabpf_action_free(psabpf_action_t *action);
void psabpf_action_set_id(psabpf_action_t *action, uint32_t action_id);
#define PSABPF_INVALID_ACTION_ID 0xFFFFFFFF
/* Returns action ID or PSABPF_INVALID_ACTION_ID on error */
uint32_t psabpf_table_get_action_id_by_name(psabpf_table_entry_ctx_t *ctx, const char *name);
int psabpf_action_param(psabpf_action_t *action, psabpf_action_param_t *param);
uint32_t psabpf_action_get_id(psabpf_table_entry_t *entry);
const char *psabpf_action_get_name(psabpf_table_entry_ctx_t *ctx, uint32_t action_id);

int psabpf_table_entry_add(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry);
int psabpf_table_entry_update(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry);
int psabpf_table_entry_del(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry);
int psabpf_table_entry_get(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry);
psabpf_table_entry_t *psabpf_table_entry_get_next(psabpf_table_entry_ctx_t *ctx);

int psabpf_table_entry_set_default_entry(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry);
int psabpf_table_entry_get_default_entry(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry);

/* DirectCounter */
void psabpf_direct_counter_ctx_init(psabpf_direct_counter_context_t *dc_ctx);
void psabpf_direct_counter_ctx_free(psabpf_direct_counter_context_t *dc_ctx);
int psabpf_direct_counter_ctx_name(psabpf_direct_counter_context_t *dc_ctx,
                                   psabpf_table_entry_ctx_t *table_ctx, const char *dc_name);

int psabpf_table_entry_set_direct_counter(psabpf_table_entry_t *entry, psabpf_direct_counter_context_t *dc_ctx,
                                          psabpf_counter_entry_t *dc);
psabpf_direct_counter_context_t *psabpf_direct_counter_get_next_ctx(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry);
psabpf_counter_type_t psabpf_direct_counter_get_type(psabpf_direct_counter_context_t *dc_ctx);
const char *psabpf_direct_counter_get_name(psabpf_direct_counter_context_t *dc_ctx);
int psabpf_direct_counter_get_entry(psabpf_direct_counter_context_t *dc_ctx, psabpf_table_entry_t *entry, psabpf_counter_entry_t *dc);

/* DirectMeter */
void psabpf_direct_meter_ctx_init(psabpf_direct_meter_context_t *dm_ctx);
void psabpf_direct_meter_ctx_free(psabpf_direct_meter_context_t *dm_ctx);
int psabpf_direct_meter_ctx_name(psabpf_direct_meter_context_t *dm_ctx,
                                 psabpf_table_entry_ctx_t *table_ctx, const char *dm_name);

int psabpf_table_entry_set_direct_meter(psabpf_table_entry_t *entry, psabpf_direct_meter_context_t *dm_ctx,
                                        psabpf_meter_entry_t *dm);
psabpf_direct_meter_context_t *psabpf_direct_meter_get_next_ctx(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry);
const char *psabpf_direct_meter_get_name(psabpf_direct_meter_context_t *dm_ctx);
int psabpf_direct_meter_get_entry(psabpf_direct_meter_context_t *dm_ctx, psabpf_table_entry_t *entry, psabpf_meter_entry_t *dm);

/*
 * Action Selector
 */

typedef struct psabpf_action_selector_member_context {
    uint32_t member_ref;
    psabpf_action_t action;
} psabpf_action_selector_member_context_t;

typedef struct psabpf_action_selector_group_context {
    uint32_t group_ref;
} psabpf_action_selector_group_context_t;

typedef struct psabpf_action_selector_context {
    psabpf_btf_t btf;

    psabpf_bpf_map_descriptor_t map_of_groups;
    psabpf_bpf_map_descriptor_t group;
    psabpf_bpf_map_descriptor_t map_of_members;
    psabpf_bpf_map_descriptor_t default_group_action;
    psabpf_bpf_map_descriptor_t cache;
} psabpf_action_selector_context_t;

void psabpf_action_selector_ctx_init(psabpf_action_selector_context_t *ctx);
void psabpf_action_selector_ctx_free(psabpf_action_selector_context_t *ctx);
int psabpf_action_selector_ctx_name(psabpf_context_t *psabpf_ctx, psabpf_action_selector_context_t *ctx, const char *name);

void psabpf_action_selector_member_init(psabpf_action_selector_member_context_t *member);
void psabpf_action_selector_member_free(psabpf_action_selector_member_context_t *member);

void psabpf_action_selector_group_init(psabpf_action_selector_group_context_t *group);
void psabpf_action_selector_group_free(psabpf_action_selector_group_context_t *group);

/* Reuse table API */
int psabpf_action_selector_member_action(psabpf_action_selector_member_context_t *member, psabpf_action_t *action);

#define PSABPF_ACTION_SELECTOR_INVALID_REFERENCE 0
uint32_t psabpf_action_selector_get_member_reference(psabpf_action_selector_member_context_t *member);
void psabpf_action_selector_set_member_reference(psabpf_action_selector_member_context_t *member, uint32_t member_ref);
uint32_t psabpf_action_selector_get_group_reference(psabpf_action_selector_group_context_t *group);
void psabpf_action_selector_set_group_reference(psabpf_action_selector_group_context_t *group, uint32_t group_ref);

int psabpf_action_selector_add_member(psabpf_action_selector_context_t *ctx, psabpf_action_selector_member_context_t *member);
int psabpf_action_selector_update_member(psabpf_action_selector_context_t *ctx, psabpf_action_selector_member_context_t *member);
int psabpf_action_selector_del_member(psabpf_action_selector_context_t *ctx, psabpf_action_selector_member_context_t *member);

int psabpf_action_selector_add_group(psabpf_action_selector_context_t *ctx, psabpf_action_selector_group_context_t *group);
int psabpf_action_selector_del_group(psabpf_action_selector_context_t *ctx, psabpf_action_selector_group_context_t *group);

int psabpf_action_selector_add_member_to_group(psabpf_action_selector_context_t *ctx,
                                               psabpf_action_selector_group_context_t *group,
                                               psabpf_action_selector_member_context_t *member);
int psabpf_action_selector_del_member_from_group(psabpf_action_selector_context_t *ctx,
                                                 psabpf_action_selector_group_context_t *group,
                                                 psabpf_action_selector_member_context_t *member);

/* Reuse table API */
int psabpf_action_selector_set_default_group_action(psabpf_action_selector_context_t *ctx, psabpf_action_t *action);
/* See psabpf_table_get_action_id_by_name() */
uint32_t psabpf_action_selector_get_action_id_by_name(psabpf_action_selector_context_t *ctx, const char *name);

/*
 * TODO: Action Profile
 */

////// PacketIn / PacketOut
// TODO: to be implemented
//  - to listen on the specified PSA_PORT_CPU interfaces
//  - to send packet out of the specified PSA_PORT_CPU interface

////// MISC
// TODO: to be implemented
//  /* Use to retrieve report about packet processing from the data plane. */
//  int psabpf_report_get_next();

#endif //__PSABPF_H
