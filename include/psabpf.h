#ifndef __PSABPF_H
#define __PSABPF_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "bpf_defs.h"

#define NO_ERROR 0

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


/*
 * PRE - Multicast Groups
 */
typedef uint32_t psabpf_mcast_grp_id_t;

typedef struct psabpf_mcast_grp_context {
    psabpf_mcast_grp_id_t id;
} psabpf_mcast_grp_ctx_t;

typedef struct psabpf_mcast_grp_member {
    uint32_t egress_port;
    uint16_t instance;
} psabpf_mcast_grp_member_t;

void psabpf_mcast_grp_context_init(psabpf_mcast_grp_ctx_t *ctx);
void psabpf_mcast_grp_context_free(psabpf_mcast_grp_ctx_t *ctx);

void psabpf_mcast_grp_id(psabpf_mcast_grp_ctx_t *ctx, psabpf_mcast_grp_id_t mcast_grp_id);

int psabpf_mcast_grp_create(psabpf_mcast_grp_ctx_t *ctx);
int psabpf_mcast_grp_exists(psabpf_mcast_grp_ctx_t *ctx);
int psabpf_mcast_grp_delete(psabpf_mcast_grp_ctx_t *ctx);

int psabpf_mcast_grp_member_init(psabpf_mcast_grp_member_t *member);
int psabpf_mcast_grp_member_free(psabpf_mcast_grp_member_t *member);

int psabpf_mcast_grp_member_port(psabpf_mcast_grp_member_t *member, uint32_t egress_port);
int psabpf_mcast_grp_member_instance(psabpf_mcast_grp_member_t *member, uint16_t instance);

int psabpf_mcast_grp_member_update(psabpf_mcast_grp_ctx_t *ctx, psabpf_mcast_grp_member_t *member);
int psabpf_mcast_grp_member_exists(psabpf_mcast_grp_ctx_t *ctx, psabpf_mcast_grp_member_t *member);
int psabpf_mcast_grp_member_delete(psabpf_mcast_grp_ctx_t *ctx, psabpf_mcast_grp_member_t *member);
// psabpf_mcast_grp_member_get does not make sense as mcast grp member does not have additional parameters

////// TableEntry
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
} psabpf_match_key_t;

typedef struct psabpf_action_param {
    char *data;  /* might be an action data or reference */
    size_t len;
    bool is_group_reference;
} psabpf_action_param_t;

typedef struct psabpf_action {
    uint32_t action_id;

    size_t n_params;
    psabpf_action_param_t *params;
} psabpf_action_t;

typedef struct psabpf_table_entry {
    size_t n_keys;
    psabpf_match_key_t **match_keys;

    psabpf_action_t *action;

    uint32_t priority;
} psabpf_table_entry_t;

typedef struct psabpf_btf {
    // BTF metadata are associated with eBPF program, eBPF map do not have own BTF
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
 * TODO: specific fields of table entry context are still to be added.
 * The table entry context may store information about a table itself (e.g. key size, num of entries, etc.).
 * It may be filled in based on the P4Info file.
 */
typedef struct psabpf_table_entry_context {
    psabpf_bpf_map_descriptor_t table;
    bool is_indirect;
    bool is_ternary;

    /* for ternary tables */
    psabpf_bpf_map_descriptor_t prefixes;
    psabpf_bpf_map_descriptor_t tuple_map;

    /* for cache maintenance */
    psabpf_bpf_map_descriptor_t cache;

    psabpf_btf_t btf_metadata;

    // below fields might be useful when iterating
    size_t curr_idx;
    psabpf_table_entry_t *prev;
} psabpf_table_entry_ctx_t;

void psabpf_table_entry_ctx_init(psabpf_table_entry_ctx_t *ctx);
void psabpf_table_entry_ctx_free(psabpf_table_entry_ctx_t *ctx);
int psabpf_table_entry_ctx_tblname(psabpf_context_t *psabpf_ctx, psabpf_table_entry_ctx_t *ctx, const char *name);
void psabpf_table_entry_ctx_mark_indirect(psabpf_table_entry_ctx_t *ctx);

void psabpf_table_entry_init(psabpf_table_entry_t *entry);
void psabpf_table_entry_free(psabpf_table_entry_t *entry);

// can be invoked multiple times
int psabpf_table_entry_matchkey(psabpf_table_entry_t *entry, psabpf_match_key_t *mk);

void psabpf_table_entry_action(psabpf_table_entry_t *entry, psabpf_action_t *act);
// only for ternary
void psabpf_table_entry_priority(psabpf_table_entry_t *entry, const uint32_t priority);

void psabpf_matchkey_init(psabpf_match_key_t *mk);
void psabpf_matchkey_free(psabpf_match_key_t *mk);
void psabpf_matchkey_type(psabpf_match_key_t *mk, enum psabpf_matchkind_t type);
int psabpf_matchkey_data(psabpf_match_key_t *mk, const char *data, size_t size);

// only for lpm
int psabpf_matchkey_prefix(psabpf_match_key_t *mk, uint32_t prefix);

// only for ternary
int psabpf_matchkey_mask(psabpf_match_key_t *mk, const char *mask, size_t size);

// only for 'range' match
int psabpf_matchkey_start(psabpf_match_key_t *mk, uint64_t start);
int psabpf_matchkey_end(psabpf_match_key_t *mk, uint64_t end);

int psabpf_action_param_create(psabpf_action_param_t *param, const char *data, size_t size);
// should be called when psabpf_action_param() is not called after psabpf_action_param_create()
void psabpf_action_param_free(psabpf_action_param_t *param);

void psabpf_action_param_mark_group_reference(psabpf_action_param_t *param);

void psabpf_action_init(psabpf_action_t *action);
void psabpf_action_free(psabpf_action_t *action);
void psabpf_action_set_id(psabpf_action_t *action, uint32_t action_id);
int psabpf_action_param(psabpf_action_t *action, psabpf_action_param_t *param);

int psabpf_table_entry_add(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry);
int psabpf_table_entry_update(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry);
int psabpf_table_entry_del(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry);
int psabpf_table_entry_get(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t **entry);
int psabpf_table_entry_getnext(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t **entry);

/**
 * Sets a default entry.
 *
 * Example code:
 *  psabpf_table_entry_t entry;
 *  if (!psabpf_table_entry_init(&entry))
 *      return;
 *  psabpf_table_entry_tblname(&entry, "xyz");
 *
 *  psabpf_action_t action;
 *  psabpf_action_init(&action);
 *  psabpf_action_setid(&action, 1);
 *  for (action params)
 *      psabpf_action_param_set(&action, "dsada", 12);
 *
 *  if (!psabpf_table_entry_setdefault(&entry))
 *      psabpf_table_entry_free(&entry);
 *      return EINVAL;
 *
 *  psabpf_table_entry_free(&entry);
 *
 * @param entry
 * @return
 */
int psabpf_table_entry_setdefault(psabpf_table_entry_t *entry);
int psabpf_table_entry_getdefault(psabpf_table_entry_t *entry);

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
int psabpf_action_selector_ctx_open(psabpf_context_t *psabpf_ctx, psabpf_action_selector_context_t *ctx, const char *name);

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

/*
 * P4 Counters
 */
// TODO: design API for Counters

typedef uint64_t psabpf_counter_value_t;

// TODO: psabpf API for counters is not done yet.
typedef struct {
    //! member validity: packets, bytes or both?
    int valid;
    psabpf_counter_value_t bytes;
    psabpf_counter_value_t packets;
} psabpf_counter_data_t;

int psabpf_counter_read(const char *name, size_t index, psabpf_counter_data_t *data);
int psabpf_counter_reset(const char *name, size_t index);

/*
 * P4 Meters
 */

typedef uint64_t psabpf_meter_value_t;

typedef struct {
    size_t index_size;
    void *index;
    psabpf_meter_value_t pbs;
    psabpf_meter_value_t pir;
    psabpf_meter_value_t cbs;
    psabpf_meter_value_t cir;
} psabpf_meter_entry_t;

typedef struct {
    int table_fd;
    uint32_t index_size;
    uint32_t value_size;
} psabpf_meter_ctx_t;

void psabpf_meter_entry_init(psabpf_meter_entry_t *entry);
void psabpf_meter_entry_free(psabpf_meter_entry_t *entry);
int psabpf_meter_entry_index(psabpf_meter_entry_t *entry, const char *data, size_t size);
int psabpf_meter_entry_data(psabpf_meter_entry_t *entry,
                            psabpf_meter_value_t pir,
                            psabpf_meter_value_t pbs,
                            psabpf_meter_value_t cir,
                            psabpf_meter_value_t cbs);

void psabpf_meter_ctx_init(psabpf_meter_ctx_t *ctx);
void psabpf_meter_ctx_free(psabpf_meter_ctx_t *ctx);
int psabpf_meter_ctx_name(psabpf_meter_ctx_t *ctx, psabpf_context_t *psabpf_ctx, const char *name);
int psabpf_meter_ctx_get(psabpf_meter_ctx_t *ctx, psabpf_meter_entry_t *entry);
int psabpf_meter_ctx_update(psabpf_meter_ctx_t *ctx, psabpf_meter_entry_t *entry);
int psabpf_meter_ctx_reset(psabpf_meter_ctx_t *ctx, psabpf_meter_entry_t *entry);

////// P4 Registers
// TODO: to be implemented

////// PacketIn / PacketOut
// TODO: to be implemented
//  - to listen on the specified PSA_PORT_CPU interfaces
//  - to send packet out of the specified PSA_PORT_CPU interface

////// MISC
// TODO: to be implemented
//  /* Use to retrieve report about packet processing from the data plane. */
//  int psabpf_report_get_next();

#endif //__PSABPF_H
