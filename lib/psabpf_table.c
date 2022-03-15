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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <linux/bpf.h>
#include <linux/btf.h>

#include <psabpf.h>
#include "btf.h"
#include "common.h"
#include "psabpf_table.h"
#include "psabpf_counter.h"
#include "psabpf_meter.h"

void psabpf_table_entry_ctx_init(psabpf_table_entry_ctx_t *ctx)
{
    if (ctx == NULL)
        return;
    memset(ctx, 0, sizeof(psabpf_table_entry_ctx_t));

    /* 0 is a valid file descriptor */
    ctx->table.fd = -1;
    ctx->default_entry.fd = -1;
    ctx->btf_metadata.associated_prog = -1;
    ctx->prefixes.fd = -1;
    ctx->tuple_map.fd = -1;
    ctx->cache.fd = -1;
}

void psabpf_table_entry_ctx_free(psabpf_table_entry_ctx_t *ctx)
{
    if (ctx == NULL)
        return;

    free_btf(&ctx->btf_metadata);

    close_object_fd(&(ctx->table.fd));
    close_object_fd(&(ctx->default_entry.fd));
    close_object_fd(&(ctx->prefixes.fd));
    close_object_fd(&(ctx->tuple_map.fd));
    close_object_fd(&(ctx->cache.fd));

    if (ctx->direct_counters_ctx != NULL) {
        for (unsigned i = 0; i < ctx->n_direct_counters; i++)
            psabpf_direct_counter_ctx_free(&ctx->direct_counters_ctx[i]);
        free(ctx->direct_counters_ctx);
        ctx->direct_counters_ctx = NULL;
    }
    ctx->n_direct_counters = 0;

    if (ctx->direct_meters_ctx != NULL) {
        for (unsigned i = 0; i < ctx->n_direct_meters; i++)
            psabpf_direct_meter_ctx_free(&ctx->direct_meters_ctx[i]);
        free(ctx->direct_meters_ctx);
        ctx->direct_meters_ctx = NULL;
    }
    ctx->n_direct_meters = 0;
}

static int get_value_type(psabpf_table_entry_ctx_t *ctx, const struct btf_type **value_type)
{
    uint32_t value_type_id = psabtf_get_member_type_id_by_name(ctx->btf_metadata.btf, ctx->table.btf_type_id, "value");
    if (value_type_id == 0)
        return ENOENT;
    *value_type = psabtf_get_type_by_id(ctx->btf_metadata.btf, value_type_id);
    if (value_type == NULL)
        return EPERM;

    if (btf_kind(*value_type) != BTF_KIND_STRUCT) {
        fprintf(stderr, "expected struct as a map value\n");
        return EPERM;
    }

    return NO_ERROR;
}

static bool member_is_direct_object(psabpf_btf_t *btf, const struct btf_member *member,
                                    const char **name, const char **type_name)
{
    *name = btf__name_by_offset(btf->btf, member->name_off);
    if (*name == NULL)
        return false;
    if (strcmp(*name, "u") == 0)
        return false;

    const struct btf_type *type = psabtf_get_type_by_id(btf->btf, member->type);
    if (type == NULL)
        return false;
    if (!btf_is_struct(type))
        return false;
    *type_name = btf__name_by_offset(btf->btf, type->name_off);
    if (*type_name == NULL)
        return false;
    if (strcmp(*type_name, "bpf_spin_lock") == 0)
        return false;

    return true;
}

static int count_direct_objects(psabpf_table_entry_ctx_t *ctx)
{
    if (ctx->btf_metadata.btf == NULL || ctx->table.btf_type_id == 0)
        return NO_ERROR;

    const struct btf_type *value_type;
    int ret = get_value_type(ctx, &value_type);
    if (ret != NO_ERROR)
        return ret;

    unsigned entries = btf_vlen(value_type);
    const struct btf_member *member = btf_members(value_type);
    for (unsigned i = 0; i < entries; i++, member++) {
        const char *member_name = NULL;
        const char *member_type_name = NULL;
        if (!member_is_direct_object(&ctx->btf_metadata, member, &member_name, &member_type_name))
            continue;

        size_t member_size = psabtf_get_type_size_by_id(ctx->btf_metadata.btf, member->type);
        psabpf_counter_type_t counter_type = get_counter_type(&ctx->btf_metadata, member->type);
        if (counter_type != PSABPF_COUNTER_TYPE_UNKNOWN) {
            /* DirectCounter */
            ctx->n_direct_counters += 1;
        } else if (strcmp(member_type_name, "meter_value") == 0 && member_size == DIRECT_METER_SIZE) {
            /* DirectMeter */
            ctx->n_direct_meters += 1;
        } else {
            fprintf(stderr, "%s: unknown type direct object instance, ignored", member_name);
            continue;
        }
    }

    return NO_ERROR;
}

static int init_direct_objects_context(psabpf_table_entry_ctx_t *ctx)
{
    if (ctx->btf_metadata.btf == NULL || ctx->table.btf_type_id == 0)
        return NO_ERROR;

    const struct btf_type *value_type;
    int ret = get_value_type(ctx, &value_type);
    if (ret != NO_ERROR)
        return ret;

    unsigned entries = btf_vlen(value_type);
    const struct btf_member *member = btf_members(value_type);
    unsigned current_counter = 0;
    unsigned current_meter = 0;
    for (unsigned i = 0; i < entries; i++, member++) {
        const char *member_name = NULL;
        const char *member_type_name = NULL;
        if (!member_is_direct_object(&ctx->btf_metadata, member, &member_name, &member_type_name))
            continue;

        size_t member_size = psabtf_get_type_size_by_id(ctx->btf_metadata.btf, member->type);
        size_t member_offset = btf_member_bit_offset(value_type, i) / 8;
        psabpf_counter_type_t counter_type = get_counter_type(&ctx->btf_metadata, member->type);

        if (counter_type != PSABPF_COUNTER_TYPE_UNKNOWN) {
            psabpf_direct_counter_ctx_init(&ctx->direct_counters_ctx[current_counter]);

            ctx->direct_counters_ctx[current_counter].name = strdup(member_name);
            ctx->direct_counters_ctx[current_counter].counter_type = counter_type;
            ctx->direct_counters_ctx[current_counter].counter_offset = member_offset;
            ctx->direct_counters_ctx[current_counter].counter_size = member_size;
            ctx->direct_counters_ctx[current_counter].counter_idx = current_counter;
            if (ctx->direct_counters_ctx[current_counter].name == NULL)
                return ENOMEM;

            ++current_counter;
        } else if (strcmp(member_type_name, "meter_value") == 0 && member_size == DIRECT_METER_SIZE) {
            psabpf_direct_meter_ctx_init(&ctx->direct_meters_ctx[current_meter]);

            ctx->direct_meters_ctx[current_meter].name = strdup(member_name);
            ctx->direct_meters_ctx[current_meter].meter_offset = member_offset;
            ctx->direct_meters_ctx[current_meter].meter_size = member_size;
            ctx->direct_meters_ctx[current_meter].meter_idx = current_meter;
            if (ctx->direct_meters_ctx[current_meter].name == NULL)
                return ENOMEM;

            ++current_meter;
        }
    }

    return NO_ERROR;
}

static int init_direct_objects(psabpf_table_entry_ctx_t *ctx)
{
    if (ctx->btf_metadata.btf == NULL || ctx->table.btf_type_id == 0) {
        fprintf(stderr, "unable to handle direct objects; resetting them if exist\n");
        return NO_ERROR;
    }

    int ret = count_direct_objects(ctx);
    if (ret != NO_ERROR)
        return ret;

    if (ctx->n_direct_counters > 0) {
        ctx->direct_counters_ctx = malloc(ctx->n_direct_counters * sizeof(psabpf_direct_counter_context_t));
        if (ctx->direct_counters_ctx == NULL)
            return ENOMEM;
    }

    if (ctx->n_direct_meters > 0) {
        ctx->direct_meters_ctx = malloc(ctx->n_direct_meters * sizeof(psabpf_direct_meter_context_t));
        if (ctx->direct_meters_ctx == NULL)
            return ENOMEM; // TODO: deallocate counter ctx to avoid mem leak or memory corruption
    }

    return init_direct_objects_context(ctx);
}

static int open_ternary_table(psabpf_context_t *psabpf_ctx, psabpf_table_entry_ctx_t *ctx, const char *name)
{
    int ret;
    char derived_name[256];

    snprintf(derived_name, sizeof(derived_name), "%s_prefixes", name);
    ret = open_bpf_map(psabpf_ctx, derived_name, &ctx->btf_metadata, &ctx->prefixes);
    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't open map %s: %s\n", derived_name, strerror(ret));
        return ret;
    }

    snprintf(derived_name, sizeof(derived_name), "%s_tuples_map", name);
    ret = open_bpf_map(psabpf_ctx, derived_name, &ctx->btf_metadata, &ctx->tuple_map);
    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't open map %s: %s\n", derived_name, strerror(ret));
        return ret;
    }

    snprintf(derived_name, sizeof(derived_name), "%s_tuple", name);
    ret = open_bpf_map(psabpf_ctx, derived_name, &ctx->btf_metadata, &ctx->table);
    close_object_fd(&(ctx->table.fd));  /* We need only metadata from this map */
    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't open map %s: %s\n", derived_name, strerror(ret));
        return ret;
    }

    ctx->is_ternary = true;

    return NO_ERROR;
}

int psabpf_table_entry_ctx_tblname(psabpf_context_t *psabpf_ctx, psabpf_table_entry_ctx_t *ctx, const char *name)
{
    if (ctx == NULL || psabpf_ctx == NULL || name == NULL)
        return EINVAL;

    /* get the BTF, it is optional so print only warning */
    if (load_btf(psabpf_ctx, &ctx->btf_metadata) != NO_ERROR)
        fprintf(stderr, "warning: couldn't find BTF info\n");

    int ret = open_bpf_map(psabpf_ctx, name, &ctx->btf_metadata, &ctx->table);

    /* if map does not exist, try the ternary table */
    if (ret == ENOENT)
        ret = open_ternary_table(psabpf_ctx, ctx, name);

    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't open table %s: %s\n", name, strerror(ret));
        return ret;
    }

    /* TODO: detect if value type contains "u" union and then threat table as direct;
     *       in other case as an indirect table (e.g. ActionProfile or ActionSelector).
     *       This may require changes in API */

    /* Open map with default entry, ignore error(s), because map is optional */
    char map_name[256];
    snprintf(map_name, sizeof(map_name), "%s_defaultAction", name);
    open_bpf_map(psabpf_ctx, map_name, &ctx->btf_metadata, &ctx->default_entry);

    /* open cache table, this is optional feature for table*/
    snprintf(map_name, sizeof(map_name), "%s_cache", name);
    ret = open_bpf_map(psabpf_ctx, map_name, &ctx->btf_metadata, &ctx->cache);
    if (ret == NO_ERROR)
        fprintf(stderr, "found cache for table: %s\n", name);

    ret = init_direct_objects(ctx);
    if (ret != NO_ERROR) {
        fprintf(stderr, "failed to initialize direct objects: %s\n", strerror(ret));
        return ret;
    }

    return NO_ERROR;
}

void psabpf_table_entry_ctx_mark_indirect(psabpf_table_entry_ctx_t *ctx)
{
    if (ctx == NULL)
        return;
    ctx->is_indirect = true;
}

bool psabpf_table_entry_ctx_is_indirect(psabpf_table_entry_ctx_t *ctx)
{
    if (ctx == NULL)
        return false;
    return ctx->is_indirect;
}

bool psabpf_table_entry_ctx_has_priority(psabpf_table_entry_ctx_t *ctx)
{
    if (ctx == NULL)
        return false;
    return ctx->is_ternary;
}

void psabpf_table_entry_init(psabpf_table_entry_t *entry)
{
    if (entry == NULL)
        return;
    memset(entry, 0, sizeof(psabpf_table_entry_t));

    psabpf_matchkey_init(&entry->current_match_key);
    psabpf_direct_counter_ctx_init(&entry->current_direct_counter_ctx);
}

void psabpf_table_entry_free(psabpf_table_entry_t *entry)
{
    if (entry == NULL)
        return;

    /* free match keys */
    for (size_t i = 0; i < entry->n_keys; i++) {
        psabpf_matchkey_free(entry->match_keys[i]);
    }
    if (entry->match_keys)
        free(entry->match_keys);
    entry->match_keys = NULL;

    /* free action data */
    if (entry->action != NULL) {
        psabpf_action_free(entry->action);
        free(entry->action);
        entry->action = NULL;
    }

    /* free DirectCounter instances */
    if (entry->direct_counters != NULL) {
        for (unsigned i = 0; i < entry->n_direct_counters; i++)
            psabpf_counter_entry_free(&entry->direct_counters[i].counter);
        free(entry->direct_counters);
    }
    entry->direct_counters = NULL;

    /* free DirectMeter instances */
    if (entry->direct_meters != NULL) {
        for (unsigned i = 0; i < entry->n_direct_meters; i++)
            psabpf_meter_entry_free(&entry->direct_meters[i].meter);
        free(entry->direct_meters);
    }
    entry->direct_meters = NULL;

    /* Iterators */
    psabpf_matchkey_free(&entry->current_match_key);
    psabpf_action_param_free(&entry->current_action_param);
    psabpf_direct_counter_ctx_free(&entry->current_direct_counter_ctx);
}

/* can be invoked multiple times */
int psabpf_table_entry_matchkey(psabpf_table_entry_t *entry, psabpf_match_key_t *mk)
{
    if (entry == NULL || mk == NULL)
        return EINVAL;
    if (mk->data == NULL)
        return ENODATA;

    if (mk->type == PSABPF_LPM) {
        for (size_t i = 0; i < entry->n_keys; ++i) {
            if (entry->match_keys[i]->type == PSABPF_LPM) {
                fprintf(stderr, "only one LPM key is allowed\n");
                return EPERM;
            }
        }
    }

    size_t new_size = (entry->n_keys + 1) * sizeof(psabpf_match_key_t *);
    psabpf_match_key_t ** tmp = malloc(new_size);
    psabpf_match_key_t * new_mk = malloc(sizeof(psabpf_match_key_t));

    if (tmp == NULL || new_mk == NULL) {
        if (tmp != NULL)
            free(tmp);
        if (new_mk != NULL)
            free(new_mk);
        return ENOMEM;
    }

    if (entry->n_keys != 0) {
        memcpy(tmp, entry->match_keys, (entry->n_keys) * sizeof(psabpf_match_key_t *));
    }
    if (entry->match_keys != NULL)
        free(entry->match_keys);
    entry->match_keys = tmp;

    memcpy(new_mk, mk, sizeof(psabpf_match_key_t));
    entry->match_keys[entry->n_keys] = new_mk;

    /* stole data from mk to new_mk */
    mk->data = NULL;
    if (mk->type == PSABPF_TERNARY)
        mk->u.ternary.mask = NULL;

    entry->n_keys += 1;

    return NO_ERROR;
}

psabpf_match_key_t *psabpf_table_entry_get_next_matchkey(psabpf_table_entry_t *entry)
{
    if (entry == NULL)
        return NULL;

    if (entry->current_match_key_id >= entry->n_keys) {
        entry->current_match_key_id = 0;
        return NULL;
    }

    memcpy(&entry->current_match_key, entry->match_keys[entry->current_match_key_id], sizeof(psabpf_match_key_t));
    entry->current_match_key.data_owner = false;
    entry->current_match_key_id += 1;

    return &entry->current_match_key;
}

void move_action(psabpf_action_t *dst, psabpf_action_t *src) {
    if (dst == NULL || src == NULL)
        return;

    /* stole action data from src */
    memcpy(dst, src, sizeof(psabpf_action_t));
    src->params = NULL;
    src->n_params = 0;
}

void psabpf_table_entry_action(psabpf_table_entry_t *entry, psabpf_action_t *act)
{
    if (entry == NULL || act == NULL)
        return;

    if (entry->action != NULL)
        return;

    entry->action = malloc(sizeof(psabpf_action_t));
    if (entry->action == NULL)
        return;
    move_action(entry->action, act);
}

/* only for ternary */
void psabpf_table_entry_priority(psabpf_table_entry_t *entry, const uint32_t priority)
{
    if (entry == NULL)
        return;
    entry->priority = priority;
}

uint32_t psabpf_table_entry_get_priority(psabpf_table_entry_t *entry)
{
    if (entry == NULL)
        return 0;
    return entry->priority;
}

void psabpf_matchkey_init(psabpf_match_key_t *mk)
{
    if (mk == NULL)
        return;
    memset(mk, 0, sizeof(psabpf_match_key_t));
    mk->data_owner = true;
}

void psabpf_matchkey_free(psabpf_match_key_t *mk)
{
    if (mk == NULL)
        return;

    if (mk->data != NULL && mk->data_owner == true)
        free(mk->data);
    mk->data = NULL;

    if (mk->type == PSABPF_TERNARY) {
        if (mk->u.ternary.mask != NULL && mk->data_owner == true)
            free(mk->u.ternary.mask);
        mk->u.ternary.mask = NULL;
    }
}

void psabpf_matchkey_type(psabpf_match_key_t *mk, enum psabpf_matchkind_t type)
{
    if (mk == NULL)
        return;
    mk->type = type;
}

int psabpf_matchkey_data(psabpf_match_key_t *mk, const char *data, size_t size)
{
    if (mk == NULL || data == NULL)
        return EINVAL;
    if (mk->data != NULL)
        return EEXIST;

    mk->data = malloc(size);
    if (mk->data == NULL)
        return ENOMEM;
    memcpy(mk->data, data, size);
    mk->key_size = size;

    return NO_ERROR;
}

enum psabpf_matchkind_t psabpf_matchkey_get_type(psabpf_match_key_t *mk)
{
    if (mk == NULL)
        return PSABPF_EXACT;
    return mk->type;
}

const void *psabpf_matchkey_get_data(psabpf_match_key_t *mk)
{
    if (mk == NULL)
        return NULL;
    return mk->data;
}

size_t psabpf_matchkey_get_data_size(psabpf_match_key_t *mk)
{
    if (mk == NULL)
        return 0;
    return mk->key_size;
}

/* only for lpm */
int psabpf_matchkey_prefix(psabpf_match_key_t *mk, uint32_t prefix)
{
    if (mk == NULL)
        return EINVAL;
    if (mk->type != PSABPF_LPM)
        return EINVAL;

    mk->u.lpm.prefix_len = prefix;

    return NO_ERROR;
}

/* only for lpm */
uint32_t psabpf_matchkey_get_prefix(psabpf_match_key_t *mk)
{
    if (mk == NULL)
        return 0;
    if (mk->type != PSABPF_LPM)
        return mk->key_size * 8;
    return mk->u.lpm.prefix_len;
}

/* only for ternary */
int psabpf_matchkey_mask(psabpf_match_key_t *mk, const char *mask, size_t size)
{
    if (mk == NULL || mask == NULL)
        return EINVAL;
    if (mk->type != PSABPF_TERNARY)
        return EINVAL;
    if (mk->u.ternary.mask != NULL)
        return EEXIST;

    mk->u.ternary.mask_size = size;
    mk->u.ternary.mask = malloc(size);
    if (mk->u.ternary.mask == NULL)
        return ENOMEM;
    memcpy(mk->u.ternary.mask, mask, size);

    return NO_ERROR;
}

/* only for ternary */
const void *psabpf_matchkey_get_mask(psabpf_match_key_t *mk)
{
    if (mk == NULL)
        return NULL;
    if (mk->type != PSABPF_TERNARY)
        return NULL;
    return mk->u.ternary.mask;
}

/* only for ternary */
size_t psabpf_matchkey_get_mask_size(psabpf_match_key_t *mk)
{
    if (mk == NULL)
        return 0;
    if (mk->type != PSABPF_TERNARY)
        return 0;
    return mk->u.ternary.mask_size;
}

/* only for 'range' match */
int psabpf_matchkey_start(psabpf_match_key_t *mk, uint64_t start)
{
    (void) mk; (void) start;
    return NO_ERROR;
}

/* only for 'range' match */
int psabpf_matchkey_end(psabpf_match_key_t *mk, uint64_t end)
{
    (void) mk; (void) end;
    return NO_ERROR;
}

int psabpf_action_param_create(psabpf_action_param_t *param, const char *data, size_t size)
{
    if (param == NULL || data == NULL)
        return EINVAL;

    param->is_group_reference = false;
    param->is_data_owner = true;

    param->len = size;
    if (size == 0) {
        param->data = NULL;
        return NO_ERROR;
    }
    param->data = malloc(size);
    if (param->data == NULL)
        return ENOMEM;
    memcpy(param->data, data, size);

    return NO_ERROR;
}

void psabpf_action_param_free(psabpf_action_param_t *param)
{
    if (param == NULL)
        return;
    if (param->data != NULL && param->is_data_owner == true)
        free(param->data);
    param->data = NULL;
}

void psabpf_action_param_mark_group_reference(psabpf_action_param_t *param)
{
    if (param == NULL)
        return;
    param->is_group_reference = true;
}

psabpf_action_param_t *psabpf_action_param_get_next(psabpf_table_entry_t *entry)
{
    if (entry == NULL)
        return NULL;
    if (entry->action == NULL)
        return NULL;

    if (entry->current_action_param_id >= entry->action->n_params) {
        entry->current_action_param_id = 0;
        return NULL;
    }

    memcpy(&entry->current_action_param,
           &entry->action->params[entry->current_action_param_id],
           sizeof(psabpf_action_param_t));
    entry->current_action_param.is_data_owner = false;

    entry->current_action_param_id += 1;

    return &entry->current_action_param;
}

void *psabpf_action_param_get_data(psabpf_action_param_t *param)
{
    if (param == NULL)
        return NULL;
    return param->data;
}

size_t psabpf_action_param_get_data_len(psabpf_action_param_t *param)
{
    if (param == NULL)
        return 0;
    return param->len;
}

const char *psabpf_action_param_get_name(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry, psabpf_action_param_t *param)
{
    if (ctx == NULL || entry == NULL || param == NULL)
        return NULL;
    if (entry->action == NULL || ctx->btf_metadata.btf == NULL || ctx->table.btf_type_id == 0)
        return NULL;

    /* Find out number of action parameters. Action parameter name is known
     * only if number of parameter from entry is equal to that number. */

    uint32_t value_type_id = psabtf_get_member_type_id_by_name(ctx->btf_metadata.btf, ctx->table.btf_type_id, "value");
    psabtf_struct_member_md_t union_md = {};
    if (psabtf_get_member_md_by_name(ctx->btf_metadata.btf, value_type_id, "u", &union_md) != NO_ERROR)
        return NULL;

    psabtf_struct_member_md_t action_md = {};
    if (psabtf_get_member_md_by_index(ctx->btf_metadata.btf, union_md.effective_type_id, entry->action->action_id, &action_md) != NO_ERROR)
        return NULL;

    const struct btf_type *action_type = psabtf_get_type_by_id(ctx->btf_metadata.btf, action_md.effective_type_id);
    if (action_type == NULL)
        return NULL;
    if (!btf_is_struct(action_type))
        return NULL;

    const unsigned number_of_params = btf_vlen(action_type);
    if (param->param_id >= number_of_params || entry->action->n_params != number_of_params)
        return NULL;

    psabtf_struct_member_md_t param_md = {};
    if (psabtf_get_member_md_by_index(ctx->btf_metadata.btf, action_md.effective_type_id, param->param_id, &param_md) != NO_ERROR)
        return NULL;

    const char *type_name = btf__name_by_offset(ctx->btf_metadata.btf, param_md.member->name_off);
    if (type_name != NULL && type_name[0] == '\0')
        return NULL;

    return type_name;
}

void psabpf_action_init(psabpf_action_t *action)
{
    if (action == NULL)
        return;
    memset(action, 0, sizeof(psabpf_action_t));
}

void psabpf_action_free(psabpf_action_t *action)
{
    if (action == NULL)
        return;

    for (size_t i = 0; i < action->n_params; i++) {
        psabpf_action_param_free(&(action->params[i]));
    }
    if (action->params != NULL)
        free(action->params);
    action->params = NULL;
}

void psabpf_action_set_id(psabpf_action_t *action, uint32_t action_id) {
    if (action == NULL)
        return;
    action->action_id = action_id;
}

int psabpf_action_param(psabpf_action_t *action, psabpf_action_param_t *param)
{
    if (action == NULL || param == NULL)
        return EINVAL;
    if (param->data == NULL && param->len != 0)
        return ENODATA;

    if (param->len == 0)
        return NO_ERROR;

    size_t new_size = (action->n_params + 1) * sizeof(psabpf_action_param_t);
    psabpf_action_param_t * tmp = malloc(new_size);

    if (tmp == NULL) {
        if (param->data != NULL)
            free(param->data);
        param->data = NULL;
        return ENOMEM;
    }

    if (action->n_params != 0) {
        memcpy(tmp, action->params, (action->n_params) * sizeof(psabpf_action_param_t));
    }
    if (action->params != NULL)
        free(action->params);
    action->params = tmp;

    memcpy(&(action->params[action->n_params]), param, sizeof(psabpf_action_param_t));
    action->params[action->n_params].param_id = action->n_params;

    /* stole data; TODO: check if data owner */
    param->data = NULL;

    action->n_params += 1;

    return NO_ERROR;
}

uint32_t psabpf_action_get_id(psabpf_table_entry_t *entry)
{
    if (entry == NULL)
        return 0;

    if (entry->action == NULL)
        return 0;
    return entry->action->action_id;
}

const char *psabpf_action_get_name(psabpf_table_entry_ctx_t *ctx, uint32_t action_id)
{
    if (ctx == NULL)
        return NULL;
    if (ctx->btf_metadata.btf == NULL || ctx->table.btf_type_id == 0)
        return NULL;

    uint32_t value_type_id = psabtf_get_member_type_id_by_name(ctx->btf_metadata.btf, ctx->table.btf_type_id, "value");
    psabtf_struct_member_md_t union_md = {};
    if (psabtf_get_member_md_by_name(ctx->btf_metadata.btf, value_type_id, "u", &union_md) != NO_ERROR)
        return NULL;

    psabtf_struct_member_md_t action_md = {};
    if (psabtf_get_member_md_by_index(ctx->btf_metadata.btf, union_md.effective_type_id, action_id, &action_md) != NO_ERROR)
        return NULL;

    const char *type_name = btf__name_by_offset(ctx->btf_metadata.btf, action_md.member->name_off);
    if (type_name != NULL && type_name[0] == '\0')
        return NULL;

    return type_name;
}

enum write_flags {
    WRITE_HOST_ORDER = 0,
    WRITE_NETWORK_ORDER
};

static int write_buffer_btf(char * buffer, size_t buffer_len, size_t offset,
                            void * data, size_t data_len, psabpf_table_entry_ctx_t *ctx,
                            uint32_t dst_type_id, const char *dst_type, enum write_flags flags)
{
    size_t data_type_len = psabtf_get_type_size_by_id(ctx->btf_metadata.btf, dst_type_id);

    if (offset + data_len > buffer_len || data_len > data_type_len) {
        fprintf(stderr, "too much data in %s "
                        "(buffer len: %zu; offset: %zu; data size: %zu; type size: %zu)\n",
                dst_type, buffer_len, offset, data_len, data_type_len);
        return EAGAIN;
    }
    if (flags == WRITE_HOST_ORDER)
        memcpy(buffer + offset, data, data_len);
    else if (flags == WRITE_NETWORK_ORDER) {
        for (size_t i = 0; i < data_len; i++) {
            buffer[offset + data_type_len - 1 - i] = ((char *) data)[i];
        }
    }

    return NO_ERROR;
}

static int fill_key_byte_by_byte(char * buffer, psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    size_t bytes_to_write = ctx->table.key_size;
    uint32_t *lpm_prefix = NULL;

    if (ctx->table.type == BPF_MAP_TYPE_LPM_TRIE) {
        const size_t prefix_size = 4;
        lpm_prefix = (uint32_t *) buffer;
        if (ctx->table.key_size < prefix_size) {
            fprintf(stderr, "key size for LPM key is lower than prefix size (4B). BUG???\n");
            return EPERM;
        }
        buffer += prefix_size;
        bytes_to_write -= prefix_size;
    }

    for (size_t i = 0; i < entry->n_keys; i++) {
        psabpf_match_key_t *mk = entry->match_keys[i];
        if (mk->key_size > bytes_to_write) {
            fprintf(stderr, "provided keys are too long\n");
            return EPERM;
        }

        if (ctx->table.type == BPF_MAP_TYPE_LPM_TRIE && mk->type == PSABPF_LPM) {
            /* copy data in network byte order (in reverse order) */
            for (size_t k = 0; k < mk->key_size; ++k)
                buffer[k] = ((char *) (mk->data))[mk->key_size - k - 1];
        } else {
            memcpy(buffer, mk->data, mk->key_size);
        }

        /* write prefix length */
        if (ctx->table.type == BPF_MAP_TYPE_LPM_TRIE && mk->type == PSABPF_LPM) {
            *lpm_prefix = (buffer - ((char *) lpm_prefix) - 4) * 8 + mk->u.lpm.prefix_len;
        }

        buffer += mk->key_size;
        bytes_to_write -= mk->key_size;
    }

    /* TODO: maybe we should ignore this case */
    if (bytes_to_write > 0) {
        fprintf(stderr, "provided keys are too short\n");
        return EPERM;
    }
    return NO_ERROR;
}

static bool is_table_dummy_key(psabpf_table_entry_ctx_t *ctx, const struct btf_type *key_type, uint32_t key_type_id) {
    if (btf_kind(key_type) != BTF_KIND_STRUCT)
        return false;

    int entries = btf_vlen(key_type);
    if (entries != 1)
        return false;

    psabtf_struct_member_md_t action_md = {};
    if (psabtf_get_member_md_by_name(ctx->btf_metadata.btf, key_type_id, "__dummy_table_key", &action_md) == NO_ERROR)
        return true;

    return false;
}

static int fill_key_btf_info(char * buffer, psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    uint32_t key_type_id = psabtf_get_member_type_id_by_name(ctx->btf_metadata.btf, ctx->table.btf_type_id, "key");
    if (key_type_id == 0)
        return EAGAIN;
    const struct btf_type *key_type = psabtf_get_type_by_id(ctx->btf_metadata.btf, key_type_id);
    if (key_type == NULL)
        return EAGAIN;

    if (btf_kind(key_type) == BTF_KIND_INT) {
        if (entry->n_keys != 1) {
            fprintf(stderr, "expected 1 key\n");
            return EAGAIN;
        }
        if (entry->match_keys[0]->key_size > ctx->table.key_size) {
            fprintf(stderr, "too much data in key\n");
            return EPERM;  /* byte by byte mode will not fix this */
        }
        memcpy(buffer, entry->match_keys[0]->data, entry->match_keys[0]->key_size);
    } else if (btf_kind(key_type) == BTF_KIND_STRUCT) {
        const struct btf_member *member = btf_members(key_type);
        unsigned entries = btf_vlen(key_type);
        unsigned expected_entries = entries;

        if (ctx->table.type == BPF_MAP_TYPE_LPM_TRIE)
            --expected_entries;  /* omit prefix length */
        if (is_table_dummy_key(ctx, key_type, key_type_id)) {
            /* Preserve zeroed bytes if table do not define key */
            expected_entries = 0;
            entries = 0;
        }
        if (entry->n_keys != expected_entries) {
            fprintf(stderr, "expected %u keys, got %zu\n", expected_entries, entry->n_keys);
            return EAGAIN;
        }

        for (unsigned member_idx = 0, key_idx = 0; member_idx < entries; member_idx++, member++) {
            if (member_idx == 0 && ctx->table.type == BPF_MAP_TYPE_LPM_TRIE)
                continue;  /* skip prefix length */

            /* assume that every field is byte aligned */
            unsigned offset = btf_member_bit_offset(key_type, member_idx) / 8;
            psabpf_match_key_t *mk = entry->match_keys[key_idx];
            int ret = 0, flags = WRITE_HOST_ORDER;

            if (ctx->table.type == BPF_MAP_TYPE_LPM_TRIE && mk->type == PSABPF_LPM)
                flags = WRITE_NETWORK_ORDER;
            ret = write_buffer_btf(buffer, ctx->table.key_size, offset, mk->data, mk->key_size,
                                   ctx, member->type, "key", flags);
            if (ret != NO_ERROR)
                return ret;

            /* write prefix value for LPM field */
            if (ctx->table.type == BPF_MAP_TYPE_LPM_TRIE && mk->type == PSABPF_LPM) {
                uint32_t prefix_value = offset * 8 + mk->u.lpm.prefix_len - 32;
                psabtf_struct_member_md_t prefix_md;
                if (psabtf_get_member_md_by_index(ctx->btf_metadata.btf, key_type_id, 0, &prefix_md) != NO_ERROR)
                    return EAGAIN;
                ret = write_buffer_btf(buffer, ctx->table.key_size, prefix_md.bit_offset / 8,
                                       &prefix_value, sizeof(prefix_value), ctx,
                                       prefix_md.effective_type_id, "prefix", WRITE_HOST_ORDER);
                if (ret != NO_ERROR)
                    return ret;
            }

            ++key_idx;
        }
    } else {
        fprintf(stderr, "unexpected BTF type for key\n");
        return EAGAIN;
    }

    return NO_ERROR;
}

static int fill_value_byte_by_byte(char * buffer, psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    size_t bytes_to_write = ctx->table.value_size;

    /* write action ID */
    if (ctx->is_indirect == false) {
        size_t action_id_len = sizeof(entry->action->action_id);
        if (action_id_len <= bytes_to_write) {
            memcpy(buffer, &(entry->action->action_id), action_id_len);
            buffer += action_id_len;
            bytes_to_write -= action_id_len;
        } else {
            fprintf(stderr, "action id do not fits into value\n");
            return EPERM;
        }
    }

    /* write priority */
    if (ctx->is_ternary) {
        size_t priority_len = sizeof(entry->priority);
        if (priority_len <= bytes_to_write) {
            memcpy(buffer, &(entry->priority), priority_len);
            buffer += priority_len;
            bytes_to_write -= priority_len;
        } else {
            fprintf(stderr, "priority do not fits into value\n");
            return EPERM;
        }
    }

    for (size_t i = 0; i < entry->action->n_params; i++) {
        psabpf_action_param_t *param = &(entry->action->params[i]);
        if (param->len > bytes_to_write) {
            fprintf(stderr, "provided values are too long\n");
            return EPERM;
        }
        memcpy(buffer, param->data, param->len);
        buffer += param->len;
        bytes_to_write -= param->len;
    }

    /* TODO: maybe we should ignore this case */
    if (bytes_to_write > 0) {
        fprintf(stderr, "provided values are too short\n");
        return EPERM;
    }
    return NO_ERROR;
}

static int fill_action_id(char * buffer, psabpf_table_entry_ctx_t *ctx,
                          psabpf_table_entry_t *entry, uint32_t value_type_id)
{
    psabtf_struct_member_md_t action_md = {};
    if (psabtf_get_member_md_by_name(ctx->btf_metadata.btf, value_type_id, "action", &action_md) != NO_ERROR) {
        fprintf(stderr, "action id entry not found\n");
        return EAGAIN;  /* Allow fallback to byte by byte mode */
    }
    return write_buffer_btf(buffer, ctx->table.value_size, action_md.bit_offset / 8,
                            &(entry->action->action_id), sizeof(entry->action->action_id),
                            ctx, action_md.effective_type_id, "action id", WRITE_HOST_ORDER);
}

static int fill_priority(char * buffer, psabpf_table_entry_ctx_t *ctx,
                         psabpf_table_entry_t *entry, uint32_t value_type_id)
{
    if (ctx->is_ternary == false)
        return NO_ERROR;

    psabtf_struct_member_md_t priority_md = {};
    if (psabtf_get_member_md_by_name(ctx->btf_metadata.btf, value_type_id, "priority", &priority_md) != NO_ERROR) {
        fprintf(stderr, "priority entry not found\n");
        return ENOENT;
    }
    return write_buffer_btf(buffer, ctx->table.value_size, priority_md.bit_offset / 8,
                            &(entry->priority), sizeof(entry->priority),
                            ctx, priority_md.effective_type_id, "priority", WRITE_HOST_ORDER);
}

static int fill_action_data(char * buffer, psabpf_table_entry_ctx_t *ctx,
                            psabpf_table_entry_t *entry, uint32_t value_type_id)
{
    size_t base_offset, offset;
    int ret;

    /* find union with action data */
    psabtf_struct_member_md_t action_union_md = {};
    if (psabtf_get_member_md_by_name(ctx->btf_metadata.btf, value_type_id, "u", &action_union_md) != NO_ERROR) {
        fprintf(stderr, "actions data structure not found\n");
        return ENOENT;
    }
    base_offset = action_union_md.bit_offset / 8;

    /* find action data structure in the union */
    psabtf_struct_member_md_t action_data_md = {};
    if (psabtf_get_member_md_by_index(ctx->btf_metadata.btf, action_union_md.effective_type_id,
                                      entry->action->action_id, &action_data_md) != NO_ERROR) {
        fprintf(stderr, "action with id %u does not exist\n", entry->action->action_id);
        return EPERM;  /* not fixable, invalid action ID */
    }
    /* to be sure of offset, take into account offset of action data structure in the union */
    base_offset = base_offset + action_data_md.bit_offset / 8;
    const struct btf_type * data_type = psabtf_get_type_by_id(ctx->btf_metadata.btf, action_data_md.effective_type_id);

    /* fill action data */
    unsigned entries = btf_vlen(data_type);
    if (entry->action->n_params != entries) {
        fprintf(stderr, "expected %d action parameters, got %zu\n",
                entries, entry->action->n_params);
        return EAGAIN;
    }
    const struct btf_member *member = btf_members(data_type);
    for (unsigned i = 0; i < entries; i++, member++) {
        offset = btf_member_bit_offset(data_type, i) / 8;
        ret = write_buffer_btf(buffer, ctx->table.value_size, base_offset + offset,
                               entry->action->params[i].data, entry->action->params[i].len,
                               ctx, member->type, "value", WRITE_HOST_ORDER);
        if (ret != NO_ERROR)
            return ret;
    }

    return NO_ERROR;
}

static int fill_action_references(char * buffer, psabpf_table_entry_ctx_t *ctx,
                                  psabpf_table_entry_t *entry, const struct btf_type *value_type)
{
    int entries = btf_vlen(value_type), ret;
    const struct btf_member *member = btf_members(value_type);
    size_t used_params = 0, offset;
    psabpf_action_param_t * current_data = &(entry->action->params[0]);
    bool entry_ref_used = false;

    for (int i = 0; i < entries; i++, member++) {
        if (used_params >= entry->action->n_params) {
            fprintf(stderr, "not enough member/group references\n");
            return EAGAIN;
        }
        const struct btf_type * member_type = psabtf_get_type_by_id(ctx->btf_metadata.btf, member->type);
        const char * member_name = btf__name_by_offset(ctx->btf_metadata.btf, member->name_off);

        /* skip errors, non-int members and reserved names */
        if (member_name == NULL || btf_kind(member_type) != BTF_KIND_INT)
            continue;
        if (strcmp(member_name, "priority") == 0 || strcmp(member_name, "action") == 0)
            continue;

        if (str_ends_with(member_name, "_is_group_ref")) {
            offset = btf_member_bit_offset(value_type, i) / 8;
            ret = write_buffer_btf(buffer, ctx->table.value_size, offset,
                                   &(current_data->is_group_reference),
                                   sizeof(current_data->is_group_reference),
                                   ctx, member->type, "reference type", WRITE_HOST_ORDER);
            if (ret != NO_ERROR)
                return ret;
            continue;
        }
        if (entry_ref_used) {
            entry_ref_used = false;
            current_data++; used_params++;
            if (used_params >= entry->action->n_params) {
                fprintf(stderr, "not enough member/group references\n");
                return EAGAIN;
            }
        }
        /* now we can write reference, hurrah!!! */
        offset = btf_member_bit_offset(value_type, i) / 8;
        ret = write_buffer_btf(buffer, ctx->table.value_size, offset, current_data->data,
                               current_data->len, ctx, member->type, "reference", WRITE_HOST_ORDER);
        if (ret != NO_ERROR)
            return ret;
        entry_ref_used = true;
    }
    if (entry_ref_used)
        used_params++;
    if (used_params != entry->action->n_params) {
        fprintf(stderr, "too many member/group references\n");
        return EAGAIN;
    }

    return NO_ERROR;
}

static int fill_value_btf_info(char * buffer, psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    int ret;

    uint32_t value_type_id = psabtf_get_member_type_id_by_name(ctx->btf_metadata.btf, ctx->table.btf_type_id, "value");
    if (value_type_id == 0)
        return EAGAIN;
    const struct btf_type *value_type = psabtf_get_type_by_id(ctx->btf_metadata.btf, value_type_id);
    if (value_type == NULL)
        return EAGAIN;

    if (btf_kind(value_type) != BTF_KIND_STRUCT) {
        fprintf(stderr, "expected struct as a map value\n");
        return EAGAIN;
    }

    if (ctx->is_indirect == false) {
        ret = fill_action_id(buffer, ctx, entry, value_type_id);
        if (ret != NO_ERROR)
            return ret;

        ret = fill_action_data(buffer, ctx, entry, value_type_id);
        if (ret != NO_ERROR)
            return ret;
    } else {
        ret = fill_action_references(buffer, ctx, entry, value_type);
        if (ret != NO_ERROR)
            return ret;
    }

    ret = fill_priority(buffer, ctx, entry, value_type_id);
    if (ret != NO_ERROR)
        return ret;

    return NO_ERROR;
}

static int lpm_prefix_to_mask(char * buffer, size_t buffer_len, uint32_t prefix, size_t data_len)
{
    unsigned ff_bytes = prefix / 8;
    size_t bytes_to_write = ff_bytes;
    if (prefix % 8 != 0)
        ++bytes_to_write;

    if (bytes_to_write > data_len || bytes_to_write > buffer_len) {
        fprintf(stderr, "LPM prefix too long\n");
        return EINVAL;
    }

    memset(buffer + data_len - ff_bytes, 0xFF, ff_bytes);
    if (prefix % 8 != 0) {
        int byte_prefix[] = {0x00, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE, 0xFF};
        memset(buffer + data_len - ff_bytes - 1, byte_prefix[prefix % 8], 1);
    }

    return NO_ERROR;
}

static int fill_key_mask_byte_by_byte(char * buffer, psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    size_t bytes_to_write = ctx->prefixes.key_size;
    for (size_t i = 0; i < entry->n_keys; i++) {
        psabpf_match_key_t *mk = entry->match_keys[i];
        size_t data_len = 0;
        if (mk->type == PSABPF_EXACT) {
            if (mk->key_size > bytes_to_write) {
                fprintf(stderr, "provided exact keys mask are too long\n");
                return EPERM;
            }
            data_len = mk->key_size;
            memset(buffer, 0xFF, data_len);
        } else if (mk->type == PSABPF_LPM) {
            data_len = mk->key_size;
            int ret = lpm_prefix_to_mask(buffer, bytes_to_write, mk->u.lpm.prefix_len, data_len);
            if (ret != NO_ERROR)
                return ret;
        } else if (mk->type == PSABPF_TERNARY) {
            if (mk->u.ternary.mask_size > bytes_to_write) {
                fprintf(stderr, "provided ternary key mask is too long\n");
                return EPERM;
            }
            if (mk->u.ternary.mask_size != mk->key_size)
                fprintf(stderr, "warning: key and its mask have different length\n");
            data_len = mk->u.ternary.mask_size;
            memcpy(buffer, mk->u.ternary.mask, data_len);
        } else {
            fprintf(stderr, "unsupported key mask type\n");
            return EAGAIN;
        }

        buffer += data_len;
        bytes_to_write -= data_len;
    }

    /* TODO: maybe we should ignore this case */
    if (bytes_to_write > 0) {
        fprintf(stderr, "provided key masks are too short\n");
        return EPERM;
    }
    return NO_ERROR;
}

static int fill_key_mask_btf(char * buffer, psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    /* Use key type to generate mask */
    uint32_t key_type_id = psabtf_get_member_type_id_by_name(ctx->btf_metadata.btf, ctx->table.btf_type_id, "key");
    if (key_type_id == 0)
        return EAGAIN;

    const struct btf_type *key_type = psabtf_get_type_by_id(ctx->btf_metadata.btf, key_type_id);
    if (key_type == NULL)
        return EAGAIN;
    if (btf_kind(key_type) != BTF_KIND_STRUCT)
        return EAGAIN;

    const struct btf_member *member = btf_members(key_type);
    unsigned entries = btf_vlen(key_type);
    if (entry->n_keys != entries) {
        fprintf(stderr, "expected %d keys, got %zu\n", entries, entry->n_keys);
        return EAGAIN;
    }

    /* Prepare temporary mask buffer for current field. Every field size <= key_size */
    char * tmp_mask = malloc(ctx->table.key_size);
    if (tmp_mask == NULL)
        return ENOMEM;

    int ret = EAGAIN;
    for (unsigned i = 0; i < entries; i++, member++) {
        psabpf_match_key_t *mk = entry->match_keys[i];
        unsigned offset = btf_member_bit_offset(key_type, i) / 8;
        size_t size = psabtf_get_type_size_by_id(ctx->btf_metadata.btf, member->type);

        ret = EAGAIN;
        memset(tmp_mask, 0, ctx->table.key_size);
        if (mk->type == PSABPF_EXACT) {
            if (size > ctx->table.key_size)
                break;
            memset(tmp_mask, 0xFF, size);
            ret = write_buffer_btf(buffer, ctx->prefixes.key_size, offset, tmp_mask, size,
                                   ctx, member->type, "exact mask key", WRITE_HOST_ORDER);
        } else if (mk->type == PSABPF_LPM) {
            ret = lpm_prefix_to_mask(tmp_mask, size, mk->u.lpm.prefix_len, size);
            if (ret != NO_ERROR) {
                ret = EAGAIN;
                break;
            }
            ret = write_buffer_btf(buffer, ctx->prefixes.key_size, offset, tmp_mask, size,
                                   ctx, member->type, "lpm mask key", WRITE_HOST_ORDER);
        } else if (mk->type == PSABPF_TERNARY) {
            ret = write_buffer_btf(buffer, ctx->prefixes.key_size, offset, mk->u.ternary.mask,
                                   mk->u.ternary.mask_size, ctx, member->type, "ternary mask key", WRITE_HOST_ORDER);
        } else {
            fprintf(stderr, "unsupported key mask type\n");
        }

        if (ret != NO_ERROR)
            break;
    }
    free(tmp_mask);

    return ret;
}

/* Please use this function instead of using directly family of fill_*() functions */
static int construct_buffer(char * buffer, size_t buffer_len,
                            psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry,
                            int (*btf_info_func)(char *, psabpf_table_entry_ctx_t *, psabpf_table_entry_t *),
                            int (*byte_by_byte_func)(char *, psabpf_table_entry_ctx_t *, psabpf_table_entry_t *))
{
    /* When BTF info mode fails we can fallback to byte by byte mode */
    int return_code = EAGAIN;
    if (ctx->btf_metadata.btf != NULL && ctx->table.btf_type_id != 0) {
        memset(buffer, 0, buffer_len);
        return_code = btf_info_func(buffer, ctx, entry);
        if (return_code == EAGAIN)
            fprintf(stderr, "falling back to byte by byte mode\n");
    }
    if (return_code == EAGAIN) {
        memset(buffer, 0, buffer_len);
        return_code = byte_by_byte_func(buffer, ctx, entry);
    }
    return return_code;
}

static int handle_direct_counter_write(const char *key, char *value, psabpf_bpf_map_descriptor_t *map,
                                       psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry, uint64_t bpf_flags)
{
    /* 1. Entry provided - build counter based on it (on update and add)
     * 2. Entry not provided - init to zero on add (already done), on update copy old value */

    if (ctx->n_direct_counters == 0)
        return NO_ERROR;

    if (bpf_flags == BPF_EXIST) {
        char *old_value_buffer = NULL;
        old_value_buffer = malloc(map->value_size);
        if (old_value_buffer == NULL)
            return ENOMEM;
        memset(old_value_buffer, 0, map->value_size);

        int err = bpf_map_lookup_elem(map->fd, key, old_value_buffer);
        if (err != 0) {
            free(old_value_buffer);
            return ENOENT;
        }

        /* copy existing values, they might be overwritten later */
        for (unsigned i = 0; i < ctx->n_direct_counters; i++) {
            memcpy(value + ctx->direct_counters_ctx[i].counter_offset,
                   old_value_buffer + ctx->direct_counters_ctx[i].counter_offset,
                   ctx->direct_counters_ctx[i].counter_size);
        }

        if (old_value_buffer != NULL)
            free(old_value_buffer);
    }

    for (unsigned i = 0; i < entry->n_direct_counters; i++) {
        unsigned idx = entry->direct_counters[i].counter_idx;
        if (idx >= ctx->n_direct_counters)
            return EINVAL;
        psabpf_direct_counter_context_t *dc_ctx = &ctx->direct_counters_ctx[idx];
        psabpf_counter_context_t counter_ctx = {
                .counter_type = dc_ctx->counter_type,
                .counter.value_size = dc_ctx->counter_size,
        };
        int ret = encode_counter_value(&counter_ctx, &entry->direct_counters[i].counter,
                                       (uint8_t *) value + ctx->direct_counters_ctx[i].counter_offset);
        if (ret != NO_ERROR)
            return ret;
    }

    return NO_ERROR;
}

static int handle_direct_meter_write(char *value, psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    /* Configure meters only when provided, otherwise leave it uninitialized */

    for (unsigned i = 0; i < entry->n_direct_meters; i++) {
        unsigned idx = entry->direct_meters[i].meter_idx;
        if (idx >= ctx->n_direct_meters)
            return EINVAL;
        psabpf_direct_meter_context_t *dm_ctx = &ctx->direct_meters_ctx[idx];
        if (dm_ctx->meter_size != DIRECT_METER_SIZE)
            return EINVAL;

        convert_meter_entry_to_data(&entry->direct_meters[i].meter,
                                    (psabpf_meter_data_t *) (value + dm_ctx->meter_offset));
    }

    return NO_ERROR;
}

static int handle_direct_objects_write(const char *key, char *value, psabpf_bpf_map_descriptor_t *map,
                                       psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry, uint64_t bpf_flags)
{
    if (ctx->is_indirect || ctx->btf_metadata.btf == NULL || ctx->table.btf_type_id == 0)
        return NO_ERROR;

    int ret = handle_direct_meter_write(value, ctx, entry);
    if (ret != NO_ERROR)
        return ret;

    return handle_direct_counter_write(key, value, map, ctx, entry, bpf_flags);
}

struct ternary_table_prefix_metadata {
    size_t tuple_id_offset;
    size_t tuple_id_size;
    size_t next_mask_offset;
    size_t next_mask_size;
    size_t has_next_offset;
    size_t has_next_size;
};

static int get_ternary_table_prefix_md(psabpf_table_entry_ctx_t *ctx, struct ternary_table_prefix_metadata *md)
{
    psabtf_struct_member_md_t member;

    md->tuple_id_size = sizeof(uint32_t);
    md->next_mask_size = ctx->table.key_size;
    md->has_next_size = sizeof(uint8_t);
    /* Lets guess offsets (they will be fixed with BTF if available) */
    md->tuple_id_offset = 0;  /* at the beginning of the structure */
    md->next_mask_offset = ctx->table.key_size > 4 ? 8 : 4;  /* after tuple_id field */
    md->has_next_offset = md->next_mask_offset + md->next_mask_size;  /* after next_mask field */

    if (ctx->btf_metadata.btf == NULL || ctx->prefixes.btf_type_id == 0)
        return NO_ERROR;

    uint32_t type_id = psabtf_get_member_type_id_by_name(ctx->btf_metadata.btf, ctx->prefixes.btf_type_id, "value");
    if (type_id == 0)
        return EPERM;

    /* tuple id */
    if (psabtf_get_member_md_by_name(ctx->btf_metadata.btf, type_id, "tuple_id", &member) != NO_ERROR)
        return EPERM;
    md->tuple_id_size = psabtf_get_type_size_by_id(ctx->btf_metadata.btf, member.effective_type_id);
    md->tuple_id_offset = member.bit_offset / 8;

    /* next mask */
    if (psabtf_get_member_md_by_name(ctx->btf_metadata.btf, type_id, "next_tuple_mask", &member) != NO_ERROR)
        return EPERM;
    md->next_mask_size = psabtf_get_type_size_by_id(ctx->btf_metadata.btf, member.effective_type_id);
    md->next_mask_offset = member.bit_offset / 8;

    /* has next */
    if (psabtf_get_member_md_by_name(ctx->btf_metadata.btf, type_id, "has_next", &member) != NO_ERROR)
        return EPERM;
    md->has_next_size = psabtf_get_type_size_by_id(ctx->btf_metadata.btf, member.effective_type_id);
    md->has_next_offset = member.bit_offset / 8;

    /* validate size and offset */
    if (md->tuple_id_offset + md->tuple_id_size > ctx->prefixes.value_size ||
        md->next_mask_offset + md->next_mask_size > ctx->prefixes.value_size ||
        md->has_next_offset + md->has_next_size > ctx->prefixes.value_size ||
        md->next_mask_size != ctx->table.key_size) {
        fprintf(stderr, "BUG: invalid size or offset in the mask\n");
        return EPERM;
    }

    return NO_ERROR;
}

static int add_ternary_table_prefix(char *new_prefix, char *prefix_value,
                                    psabpf_table_entry_ctx_t *ctx)
{
    int err = NO_ERROR;
    uint32_t tuple_id = 0;
    struct ternary_table_prefix_metadata prefix_md;

    if (get_ternary_table_prefix_md(ctx, &prefix_md) != NO_ERROR) {
        fprintf(stderr, "failed to obtain offsets and sizes of prefix\n");
        return EPERM;
    }

    char *key = malloc(ctx->prefixes.key_size);
    char *value = malloc(ctx->prefixes.value_size);
    if (key == NULL || value == NULL) {
        fprintf(stderr, "not enough memory\n");
        err = ENOMEM;
        goto clean_up;
    }

    /* Process head */
    memset(key, 0, ctx->prefixes.key_size);
    err = bpf_map_lookup_elem(ctx->prefixes.fd, key, value);
    if (err != 0) {
        /* Construct head, it will be added later */
        memset(value, 0, ctx->prefixes.value_size);
        *((uint32_t *) (value + prefix_md.tuple_id_offset)) = tuple_id;
    }

    /* Iterate over every prefix to the last one */
    while (true) {
        uint8_t has_next = *((uint8_t *) (value + prefix_md.has_next_offset));
        if (has_next == 0)
            break;

        /* Get next prefix */
        memcpy(key, value + prefix_md.next_mask_offset, prefix_md.next_mask_size);
        err = bpf_map_lookup_elem(ctx->prefixes.fd, key, value);
        if (err != 0) {
            err = errno;
            fprintf(stderr, "detected data inconsistency in prefixes, aborting\n");
            goto clean_up;
        }

        /* Find highest tuple id */
        uint32_t current_tuple_id = *((uint32_t *) (value + prefix_md.tuple_id_offset));
        if (current_tuple_id > tuple_id)
            tuple_id = current_tuple_id;
    }

    /* First add new prefix to avoid data inconsistency */
    memset(prefix_value, 0, ctx->prefixes.value_size);
    *((uint32_t *) (prefix_value + prefix_md.tuple_id_offset)) = ++tuple_id;
    err = bpf_map_update_elem(ctx->prefixes.fd, new_prefix, prefix_value, BPF_NOEXIST);
    if (err != 0)
        goto clean_up;

    /* Update previous node */
    memcpy(value + prefix_md.next_mask_offset, new_prefix, prefix_md.next_mask_size);
    *((uint8_t *) (value + prefix_md.has_next_offset)) = 1;
    err = bpf_map_update_elem(ctx->prefixes.fd, key, value, BPF_ANY);
    if (err != 0)
        goto clean_up;

    err = NO_ERROR;

clean_up:
    if (key != NULL)
        free(key);
    if (value != NULL)
        free(value);

    return err;
}

static int ternary_table_add_tuple_and_open(psabpf_table_entry_ctx_t *ctx, const uint32_t tuple_id)
{
    int err;

    struct bpf_create_map_attr attr = {
            .key_size = ctx->table.key_size,
            .value_size = ctx->table.value_size,
            .max_entries = ctx->table.max_entries,
            .map_type = ctx->table.type,
    };
    ctx->table.fd = bpf_create_map_xattr(&attr);
    if (ctx->table.fd < 0) {
        err = errno;
        fprintf(stderr, "failed to create tuple %u: %s\n", tuple_id, strerror(err));
        return err;
    }

    /* add tuple to tuples map */
    err = bpf_map_update_elem(ctx->tuple_map.fd, &tuple_id, &(ctx->table.fd), 0);
    if (err != 0) {
        err = errno;
        fprintf(stderr, "failed to add tuple %u: %s\n", tuple_id, strerror(err));
        close_object_fd(&(ctx->table.fd));
    }

    return err;
}

static int ternary_table_open_tuple(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry,
                                    char **key_mask, uint64_t bpf_flags)
{
    if (ctx->prefixes.fd < 0 || ctx->tuple_map.fd < 0 || ctx->table.fd >= 0) {
        fprintf(stderr, "ternary table not properly opened. BUG?\n");
        return EINVAL;
    }
    if (ctx->table.key_size != ctx->prefixes.key_size) {
        fprintf(stderr, "key and its mask have different length. BUG?\n");
        return EINVAL;
    }
    if (ctx->tuple_map.key_size != 4 || ctx->tuple_map.value_size != 4) {
        fprintf(stderr, "key/value size of tuples map have to be 4B.\n");
        return EINVAL;
    }

    int err = NO_ERROR;
    char *value_mask = malloc(ctx->prefixes.value_size);
    *key_mask = malloc(ctx->prefixes.key_size);

    if (*key_mask == NULL || value_mask == NULL) {
        fprintf(stderr, "not enough memory\n");
        err = ENOMEM;
        goto clean_up;
    }
    memset(*key_mask, 0, ctx->prefixes.key_size);
    memset(value_mask, 0, ctx->prefixes.value_size);

    err = construct_buffer(*key_mask, ctx->prefixes.key_size, ctx, entry,
                           fill_key_mask_btf, fill_key_mask_byte_by_byte);
    if (err != NO_ERROR)
        goto clean_up;

    /* prefixes head protection - check whether mask is different from all 0 */
    bool mask_is_valid = false;
    for (unsigned i = 0; i < ctx->prefixes.key_size; i++) {
        if ((*key_mask)[i] != 0) {
            mask_is_valid = true;
            break;
        }
    }
    if (mask_is_valid == false) {
        fprintf(stderr, "invalid key mask: all bytes are zeroed - use default action instead\n");
        err = EINVAL;
        goto clean_up;
    }

    err = bpf_map_lookup_elem(ctx->prefixes.fd, *key_mask, value_mask);
    /* It is not allowed to add new prefix when updating existing entry */
    if (err != 0 && bpf_flags != BPF_EXIST) {
        err = add_ternary_table_prefix(*key_mask, value_mask, ctx);
        if (err != NO_ERROR) {
            fprintf(stderr, "unable to add new prefix\n");
            goto clean_up;
        }
    } else if (err != 0) {
        fprintf(stderr, "entry with prefix not found\n");
        err = ENOENT;
        goto clean_up;
    }

    struct ternary_table_prefix_metadata prefix_md;
    if (get_ternary_table_prefix_md(ctx, &prefix_md) != NO_ERROR) {
        fprintf(stderr, "failed to obtain offsets and sizes of prefix\n");
        err = EPERM;
        goto clean_up;
    }
    uint32_t tuple_id = *((uint32_t *) (value_mask + prefix_md.tuple_id_offset));
    uint32_t inner_map_id;

    err = bpf_map_lookup_elem(ctx->tuple_map.fd, &tuple_id, &inner_map_id);
    if (err == 0) {
        ctx->table.fd = bpf_map_get_fd_by_id(inner_map_id);
        err = NO_ERROR;
    } else {
        if (bpf_flags == BPF_EXIST) {
            fprintf(stderr, "tuple not found\n");
            err = ENOENT;
            goto clean_up;
        }
        err = ternary_table_add_tuple_and_open(ctx, tuple_id);
    }

clean_up:
    if (value_mask != NULL)
        free(value_mask);

    return err;
}

static void ternary_table_close_tuple(psabpf_table_entry_ctx_t *ctx)
{
    /* Allow for reuse table context with the same table but other tuple (inner map). */
    if (ctx->is_ternary)
        close_object_fd(&(ctx->table.fd));
}

static int delete_all_table_entries(int fd, size_t key_size)
{
    fprintf(stderr, "removing all entries from table\n");

    char * key = malloc(key_size);
    char * next_key = malloc(key_size);
    int error_code = NO_ERROR;

    if (key == NULL || next_key == NULL) {
        fprintf(stderr, "not enough memory\n");
        error_code = ENOMEM;
        goto clean_up;
    }

    if (bpf_map_get_next_key(fd, NULL, next_key) != 0)
        goto clean_up;  /* table empty */
    do {
        /* Swap buffers, so next_key will become key and next_key may be reused */
        char * tmp_key = next_key;
        next_key = key;
        key = tmp_key;

        /* Ignore error(s) from bpf_map_delete_elem(). In some cases key may exist
         * but entry not exists (e.g. array map in map). So in any case we have to
         * iterate over all keys and try to delete it. */
        bpf_map_delete_elem(fd, key);
    } while (bpf_map_get_next_key(fd, key, next_key) == 0);

clean_up:
    if (key)
        free(key);
    if (next_key)
        free(next_key);
    return error_code;
}

int clear_table_cache(psabpf_bpf_map_descriptor_t *map)
{
    if (map == NULL || map->fd < 0)
        return NO_ERROR;

    fprintf(stderr, "clearing table cache: ");
    return delete_all_table_entries(map->fd, map->key_size);
}

static int psabpf_table_entry_write(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry, uint64_t bpf_flags)
{
    char *key_buffer = NULL;
    char *key_mask_buffer = NULL;
    char *value_buffer = NULL;
    int return_code = NO_ERROR;

    if (ctx == NULL || entry == NULL)
        return EINVAL;

    if (ctx->is_ternary) {
        return_code = ternary_table_open_tuple(ctx, entry, &key_mask_buffer, bpf_flags);
        if (return_code != NO_ERROR)
            goto clean_up;
    }

    if (ctx->table.fd < 0) {
        fprintf(stderr, "can't add entry: table not opened\n");
        goto clean_up;
    }
    if (ctx->table.key_size == 0 || ctx->table.value_size == 0) {
        fprintf(stderr, "zero-size key or value is not supported\n");
        goto clean_up;
    }
    if (entry->action == NULL) {
        fprintf(stderr, "missing action specification\n");
        goto clean_up;
    }

    /* prepare buffers for map key/value */
    key_buffer = malloc(ctx->table.key_size);
    value_buffer = malloc(ctx->table.value_size);
    if (key_buffer == NULL || value_buffer == NULL) {
        fprintf(stderr, "not enough memory\n");
        return_code = ENOMEM;
        goto clean_up;
    }

    return_code = construct_buffer(key_buffer, ctx->table.key_size, ctx, entry,
                                   fill_key_btf_info, fill_key_byte_by_byte);
    if (return_code != NO_ERROR) {
        fprintf(stderr, "failed to construct key\n");
        goto clean_up;
    }

    return_code = construct_buffer(value_buffer, ctx->table.value_size, ctx, entry,
                                   fill_value_btf_info, fill_value_byte_by_byte);
    if (return_code != NO_ERROR) {
        fprintf(stderr, "failed to construct value\n");
        goto clean_up;
    }

    if (ctx->is_ternary == true && key_mask_buffer != NULL)
        mem_bitwise_and((uint32_t *) key_buffer, (uint32_t *) key_mask_buffer, ctx->table.key_size);

    /* Handle direct objects */
    return_code = handle_direct_objects_write(key_buffer, value_buffer, &ctx->table, ctx, entry, bpf_flags);
    if (return_code != NO_ERROR) {
        fprintf(stderr, "failed to handle direct objects: %s\n", strerror(return_code));
        goto clean_up;
    }

    /* update map */
    if (ctx->table.type == BPF_MAP_TYPE_ARRAY)
        bpf_flags = BPF_ANY;
    return_code = bpf_map_update_elem(ctx->table.fd, key_buffer, value_buffer, bpf_flags);
    if (return_code != 0) {
        return_code = errno;
        fprintf(stderr, "failed to set up entry: %s\n", strerror(errno));
    } else {
        return_code = clear_table_cache(&ctx->cache);
        if (return_code != NO_ERROR) {
            fprintf(stderr, "failed to clear cache: %s\n", strerror(return_code));
        }
    }

clean_up:
    if (key_buffer != NULL)
        free(key_buffer);
    if (key_mask_buffer != NULL)
        free(key_mask_buffer);
    if (value_buffer != NULL)
        free(value_buffer);

    if (ctx->is_ternary)
        ternary_table_close_tuple(ctx);

    return return_code;
}

int psabpf_table_entry_add(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    return psabpf_table_entry_write(ctx, entry, BPF_NOEXIST);
}

int psabpf_table_entry_update(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    return psabpf_table_entry_write(ctx, entry, BPF_EXIST);
}

static int prepare_ternary_table_delete(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry, char **key_mask)
{
    if (entry->n_keys != 0)
        return ternary_table_open_tuple(ctx, entry, key_mask, BPF_EXIST);

    delete_all_table_entries(ctx->prefixes.fd, ctx->prefixes.key_size);
    fprintf(stderr, "removing entries from tuples_map, this may take a while\n");
    delete_all_table_entries(ctx->tuple_map.fd, ctx->tuple_map.key_size);

    /* Unpinning inner maps for our table is not required
     * because they are not pinned by this tool. */

    return NO_ERROR;
}

static int ternary_table_remove_prefix(psabpf_table_entry_ctx_t *ctx, const char *key_mask)
{
    int err = NO_ERROR;
    char *prev_key_mask = malloc(ctx->prefixes.key_size);
    char *prev_value_mask = malloc(ctx->prefixes.value_size);
    char *value_mask = malloc(ctx->prefixes.value_size);

    if (prev_key_mask == NULL || prev_value_mask == NULL || value_mask == NULL) {
        fprintf(stderr, "not enough memory\n");
        err = ENOMEM;
        goto clean_up;
    }

    if (bpf_map_lookup_elem(ctx->prefixes.fd, key_mask, value_mask) != 0) {
        err = errno;
        fprintf(stderr, "unable to obtain prefix: %s\n", strerror(err));
        goto clean_up;
    }

    struct ternary_table_prefix_metadata prefix_md;
    if ((err = get_ternary_table_prefix_md(ctx, &prefix_md)) != NO_ERROR) {
        fprintf(stderr, "failed to obtain offsets and sizes of prefix\n");
        goto clean_up;
    }

    /* find previous prefix */
    bool prev_prefix_found = false;
    memset(prev_key_mask, 0, ctx->prefixes.key_size);
    err = bpf_map_lookup_elem(ctx->prefixes.fd, prev_key_mask, prev_value_mask);
    if (err != 0) {
        err = errno;
        fprintf(stderr, "head not found: %s\n", strerror(err));
        goto clean_up;
    }

    while (true) {
        /* it is an previous prefix? */
        if (memcmp(prev_value_mask + prefix_md.next_mask_offset, key_mask, prefix_md.next_mask_size) == 0) {
            prev_prefix_found = true;
            break;
        }

        /* get next prefix */
        uint8_t has_next = *((uint8_t *) (prev_value_mask + prefix_md.has_next_offset));
        if (has_next == 0)
            break;
        memcpy(prev_key_mask, prev_value_mask + prefix_md.next_mask_offset, prefix_md.next_mask_size);
        if (bpf_map_lookup_elem(ctx->prefixes.fd, prev_key_mask, prev_value_mask) != 0)
            break;
    }

    if (prev_prefix_found == false) {
        fprintf(stderr, "detected data inconsistency in prefixes: no previous prefix\n");
    } else {
        /* copy next_mask and has_next to the previous prefix */
        memcpy(prev_value_mask + prefix_md.next_mask_offset,
               value_mask + prefix_md.next_mask_offset, prefix_md.next_mask_size);
        memcpy(prev_value_mask + prefix_md.has_next_offset,
               value_mask + prefix_md.has_next_offset, prefix_md.has_next_size);

        err = bpf_map_update_elem(ctx->prefixes.fd, prev_key_mask, prev_value_mask, BPF_EXIST);
        if (err != 0) {
            err = errno;
            fprintf(stderr, "failed to update previous prefix: %s\n", strerror(err));
            goto clean_up;
        }
    }

    /* there are no prefixes that points to removing prefix, so it can be safely removed now */
    if (bpf_map_delete_elem(ctx->prefixes.fd, key_mask) != 0)
        fprintf(stderr, "warning: failed to remove prefix from prefixes list\n");

    /* also remove tuple from tuple_map */
    uint32_t tuple_id = *((uint32_t *) (value_mask + prefix_md.tuple_id_offset));
    if (bpf_map_delete_elem(ctx->tuple_map.fd, &tuple_id) != 0)
        fprintf(stderr, "warning: failed to remove tuple from tuples_map\n");

    /* unpinning not required - inner map is not pinned by this tool*/

    err = NO_ERROR;

clean_up:
    if (prev_key_mask != NULL)
        free(prev_key_mask);
    if (prev_value_mask != NULL)
        free(prev_value_mask);
    if (value_mask != NULL)
        free(value_mask);

    return err;
}

static int post_ternary_table_delete(psabpf_table_entry_ctx_t *ctx, const char *key_mask)
{
    if (ctx->is_ternary == false || ctx->table.fd < 0)
        return NO_ERROR;
    if (key_mask == NULL)
        return ENODATA;

    int err = NO_ERROR;
    char *tuple_next_key = malloc(ctx->table.key_size);

    if (tuple_next_key == NULL) {
        fprintf(stderr, "not enough memory\n");
        err = ENOMEM;
        goto clean_up;
    }

    if (bpf_map_get_next_key(ctx->table.fd, NULL, tuple_next_key) != 0) {
        err = ternary_table_remove_prefix(ctx, key_mask);
    }

clean_up:
    if (tuple_next_key != NULL)
        free(tuple_next_key);

    close_object_fd(&(ctx->table.fd));
    return err;
}

int psabpf_table_entry_del(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    char *key_buffer = NULL;
    char *key_mask_buffer = NULL;
    int return_code = NO_ERROR;

    if (ctx == NULL || entry == NULL)
        return EINVAL;

    if (ctx->is_ternary) {
        return_code = prepare_ternary_table_delete(ctx, entry, &key_mask_buffer);
        if (return_code != NO_ERROR) {
            fprintf(stderr, "failed to prepare ternary table for delete\n");
            goto clean_up;
        }
        if (entry->n_keys == 0)
            goto clean_up;
    }

    if (ctx->table.fd < 0) {
        fprintf(stderr, "can't delete entry: table not opened\n");
        return EBADF;
    }
    if (ctx->table.key_size == 0) {
        fprintf(stderr, "zero-size key is not supported\n");
        return ENOTSUP;
    }

    /* remove all entries from table if key is not present */
    if (entry->n_keys == 0) {
        if (ctx->table.type == BPF_MAP_TYPE_ARRAY)
            fprintf(stderr, "removing entries from array map may take a while\n");
        return_code = delete_all_table_entries(ctx->table.fd, ctx->table.key_size);
        if (return_code == NO_ERROR) {
            return_code = clear_table_cache(&ctx->cache);
            if (return_code != NO_ERROR) {
                fprintf(stderr, "failed to clear table cache: %s\n", strerror(return_code));
            }
        }
        return return_code;
    }

    /* prepare buffers for map key */
    key_buffer = malloc(ctx->table.key_size);
    if (key_buffer == NULL) {
        fprintf(stderr, "not enough memory\n");
        return_code = ENOMEM;
        goto clean_up;
    }

    return_code = construct_buffer(key_buffer, ctx->table.key_size, ctx, entry,
                                   fill_key_btf_info, fill_key_byte_by_byte);
    if (return_code != NO_ERROR) {
        fprintf(stderr, "failed to construct key\n");
        goto clean_up;
    }

    if (ctx->is_ternary == true && key_mask_buffer != NULL)
        mem_bitwise_and((uint32_t *) key_buffer, (uint32_t *) key_mask_buffer, ctx->table.key_size);

    /* delete pointed entry */
    return_code = bpf_map_delete_elem(ctx->table.fd, key_buffer);
    if (return_code != 0) {
        return_code = errno;
        fprintf(stderr, "failed to delete entry: %s\n", strerror(errno));
    } else {
        return_code = clear_table_cache(&ctx->cache);
        if (return_code != NO_ERROR) {
            fprintf(stderr, "failed to clear cache: %s\n", strerror(return_code));
        }
    }

clean_up:
    /* cleanup ternary table */
    if (ctx->is_ternary)
        post_ternary_table_delete(ctx, key_mask_buffer);

    if (key_buffer != NULL)
        free(key_buffer);
    if (key_mask_buffer != NULL)
        free(key_mask_buffer);

    return return_code;
}

int psabpf_table_entry_set_default_entry(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    /* For default entry array map is used, it always has key 32-bit width and its value is assumed to be 0. */
    const uint32_t key = 0;
    char *value_buffer = NULL;
    int return_code = NO_ERROR;

    if (ctx == NULL || entry == NULL)
        return EINVAL;

    if (ctx->default_entry.fd < 0) {
        fprintf(stderr, "can't add default entry: table not opened or table has no default entry\n");
        return EBADF;
    }
    if (ctx->default_entry.key_size != sizeof(key) ||
        ctx->default_entry.value_size == 0 || ctx->default_entry.value_size != ctx->table.value_size) {
        fprintf(stderr, "key size or value is not supported\n");
        return ENOTSUP;
    }
    if (entry->action == NULL) {
        fprintf(stderr, "missing action specification\n");
        return ENODATA;
    }

    /* prepare buffer for map value */
    value_buffer = malloc(ctx->default_entry.value_size);
    if (value_buffer == NULL) {
        fprintf(stderr, "not enough memory\n");
        return ENOMEM;
    }

    return_code = construct_buffer(value_buffer, ctx->default_entry.value_size, ctx, entry,
                                   fill_value_btf_info, fill_value_byte_by_byte);
    if (return_code != NO_ERROR) {
        fprintf(stderr, "failed to construct value\n");
        goto clean_up;
    }

    /* Handle direct objects - default entry always exists
     * and is treated like a regular entry, including with regards to direct resources */
    return_code = handle_direct_objects_write((void *) &key, value_buffer, &ctx->default_entry, ctx, entry, BPF_EXIST);
    if (return_code != NO_ERROR) {
        fprintf(stderr, "failed to handle direct objects: %s\n", strerror(return_code));
        goto clean_up;
    }

    /* update map */
    return_code = bpf_map_update_elem(ctx->default_entry.fd, &key, value_buffer, BPF_ANY);
    if (return_code != 0) {
        return_code = errno;
        fprintf(stderr, "failed to set up entry: %s\n", strerror(errno));
    } else {
        return_code = clear_table_cache(&ctx->cache);
        if (return_code != NO_ERROR) {
            fprintf(stderr, "failed to clear cache: %s\n", strerror(return_code));
        }
    }

clean_up:
    if (value_buffer != NULL)
        free(value_buffer);

    return return_code;
}

static int parse_table_value_no_btf(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry, const void *value)
{
    size_t buffer_size = ctx->table.value_size;

    /* Action ID */
    if (ctx->is_indirect == false) {
        if (buffer_size < sizeof(uint32_t)) {
            fprintf(stderr, "too small value type\n");
            return EINVAL;
        }
        entry->action->action_id = *((uint32_t *) value);
        value += sizeof(uint32_t);
        buffer_size -= sizeof(uint32_t);
    }

    /* Priority */
    if (ctx->is_ternary) {
        if (buffer_size < sizeof(uint32_t)) {
            fprintf(stderr, "too small value type\n");
            return EINVAL;
        }
        entry->priority = *((uint32_t *) value);
        value += sizeof(uint32_t);
        buffer_size -= sizeof(uint32_t);
    }

    /* Action data, without BTF we can only return binary blob */
    if (buffer_size > 0) {
        entry->action->params = malloc(sizeof(psabpf_action_param_t));
        if (entry->action->params == NULL)
            return ENOMEM;
        entry->action->n_params = 1;
        return psabpf_action_param_create(&entry->action->params[0], value, buffer_size);
    }

    return NO_ERROR;
}

static int parse_table_value_action(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry,
                                    const void *value, uint32_t value_type_id)
{
    /* Get action ID */
    psabtf_struct_member_md_t action_id_md = {};
    if (psabtf_get_member_md_by_name(ctx->btf_metadata.btf, value_type_id, "action", &action_id_md) != NO_ERROR)
        return ENOENT;
    size_t action_id_size = psabtf_get_type_size_by_id(ctx->btf_metadata.btf, action_id_md.effective_type_id);
    if (action_id_size > sizeof(entry->action->action_id))
        return EINVAL;
    entry->action->action_id = 0;
    memcpy(&entry->action->action_id, value + action_id_md.bit_offset / 8, action_id_size);

    /* Get action params */
    psabtf_struct_member_md_t union_md = {};
    if (psabtf_get_member_md_by_name(ctx->btf_metadata.btf, value_type_id, "u", &union_md) != NO_ERROR)
        return EINVAL;
    psabtf_struct_member_md_t action_md = {};
    if (psabtf_get_member_md_by_index(ctx->btf_metadata.btf, union_md.effective_type_id, entry->action->action_id, &action_md) != NO_ERROR)
        return EINVAL;

    const struct btf_type *action_type = psabtf_get_type_by_id(ctx->btf_metadata.btf, action_md.effective_type_id);
    if (action_type == NULL)
        return EINVAL;
    if (!btf_is_struct(action_type))
        return EINVAL;

    const unsigned number_of_params = btf_vlen(action_type);
    if (number_of_params == 0)
        return NO_ERROR;
    entry->action->params = malloc(number_of_params * sizeof(psabpf_action_param_t));
    if (entry->action->params == NULL)
        return ENOMEM;
    entry->action->n_params = number_of_params;

    const size_t base_offset = (union_md.bit_offset + action_md.bit_offset) / 8;
    const struct btf_member *member = btf_members(action_type);
    for (unsigned i = 0; i < number_of_params; i++, member++) {
        psabtf_struct_member_md_t param_md = {};
        if (psabtf_get_member_md_by_index(ctx->btf_metadata.btf, action_md.effective_type_id, i, &param_md) != NO_ERROR)
            return EINVAL;

        size_t offset = base_offset + param_md.bit_offset / 8;
        size_t size = psabtf_get_type_size_by_id(ctx->btf_metadata.btf, param_md.effective_type_id);
        if (size + offset > ctx->table.value_size)
            return EINVAL;
        int ret = psabpf_action_param_create(&entry->action->params[i], value + offset, size);
        entry->action->params[i].param_id = i;
        if (ret != NO_ERROR)
            return ret;
    }

    return NO_ERROR;
}

static int parse_table_value_priority(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry,
                                      const void *value, uint32_t value_type_id)
{
    if (ctx->is_ternary == false)
        return NO_ERROR;

    psabtf_struct_member_md_t priority_md = {};
    if (psabtf_get_member_md_by_name(ctx->btf_metadata.btf, value_type_id, "priority", &priority_md) != NO_ERROR)
        return ENOENT;
    size_t size = psabtf_get_type_size_by_id(ctx->btf_metadata.btf, priority_md.effective_type_id);
    if (size > sizeof(entry->priority))
        return EINVAL;
    entry->priority = 0;
    memcpy(&entry->priority, value + priority_md.bit_offset / 8, size);

    return NO_ERROR;
}

static int parse_table_value_direct_counter(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry,
                                            const void *value)
{
    if (ctx->n_direct_counters == 0)
        return NO_ERROR;

    entry->direct_counters = malloc(ctx->n_direct_counters * sizeof(psabpf_direct_counter_entry_t));
    if (entry->direct_counters == NULL)
        return ENOMEM;

    for (unsigned i = 0; i < ctx->n_direct_counters; i++) {
        psabpf_counter_entry_init(&entry->direct_counters[i].counter);
        entry->direct_counters[i].counter_idx = ctx->direct_counters_ctx->counter_idx;
        decode_counter_value(&entry->direct_counters[i].counter,
                             value + ctx->direct_counters_ctx[i].counter_offset,
                             ctx->direct_counters_ctx[i].counter_size,
                             ctx->direct_counters_ctx[i].counter_type);
    }
    entry->n_direct_counters = ctx->n_direct_counters;

    return NO_ERROR;
}

static int parse_table_value_direct_objects(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry, const void *value)
{
    int ret = parse_table_value_direct_counter(ctx, entry, value);
    if (ret != NO_ERROR)
        return ret;

    return NO_ERROR;
}

static int parse_table_value_btf_info(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry, const void *value)
{
    int ret;
    uint32_t value_type_id = psabtf_get_member_type_id_by_name(ctx->btf_metadata.btf, ctx->table.btf_type_id, "value");
    if (value_type_id == 0)
        return ENOENT;

    if (ctx->is_indirect == false) {
        ret = parse_table_value_action(ctx, entry, value, value_type_id);
        if (ret != NO_ERROR)
            return ret;
    } else {
        /* TODO: references */
    }

    ret = parse_table_value_priority(ctx, entry, value, value_type_id);
    if (ret != NO_ERROR)
        return ret;

    ret = parse_table_value_direct_objects(ctx, entry, value);
    if (ret != NO_ERROR)
        return ret;

    return NO_ERROR;
}

static int parse_table_value(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry, const void *value)
{
    if (entry->action != NULL)
        psabpf_action_free(entry->action);
    else
        entry->action = malloc(sizeof(psabpf_action_t));
    if (entry->action == NULL)
        return ENOMEM;
    psabpf_action_init(entry->action);

    if (ctx->btf_metadata.btf == NULL || ctx->table.btf_type_id == 0)
        return parse_table_value_no_btf(ctx, entry, value);

    return parse_table_value_btf_info(ctx, entry, value);
}

int psabpf_table_entry_get(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    char *key_buffer = NULL;
    char *key_mask_buffer = NULL;
    char *value_buffer = NULL;
    int return_code = NO_ERROR;

    if (ctx == NULL || entry == NULL)
        return EINVAL;

    if (entry->n_keys == 0 || entry->match_keys == NULL) {
        fprintf(stderr, "can't get entry: missing key\n");
        return ENODATA;
    }

    if (ctx->is_ternary) {
        return_code = ternary_table_open_tuple(ctx, entry, &key_mask_buffer, BPF_EXIST);
        if (return_code != NO_ERROR)
            goto clean_up;
    }

    if (ctx->table.fd < 0) {
        fprintf(stderr, "can't get entry: table not opened\n");
        goto clean_up;
    }
    if (ctx->table.key_size == 0 || ctx->table.value_size == 0) {
        fprintf(stderr, "zero-size key or value is not supported\n");
        goto clean_up;
    }

    /* Prepare entry - remove everything but not key */
    size_t tmp_n_keys = entry->n_keys;
    entry->n_keys = 0;
    void *tmp_keys = entry->match_keys;
    entry->match_keys = NULL;
    psabpf_table_entry_free(entry);
    psabpf_table_entry_init(entry);
    entry->n_keys = tmp_n_keys;
    entry->match_keys = tmp_keys;

    /* prepare buffers for map key/value */
    key_buffer = malloc(ctx->table.key_size);
    value_buffer = malloc(ctx->table.value_size);
    if (key_buffer == NULL || value_buffer == NULL) {
        fprintf(stderr, "not enough memory\n");
        return_code = ENOMEM;
        goto clean_up;
    }

    return_code = construct_buffer(key_buffer, ctx->table.key_size, ctx, entry,
                                   fill_key_btf_info, fill_key_byte_by_byte);
    if (return_code != NO_ERROR) {
        fprintf(stderr, "failed to construct key\n");
        goto clean_up;
    }
    if (ctx->is_ternary == true && key_mask_buffer != NULL)
        mem_bitwise_and((uint32_t *) key_buffer, (uint32_t *) key_mask_buffer, ctx->table.key_size);

    return_code = bpf_map_lookup_elem(ctx->table.fd, key_buffer, value_buffer);
    if (return_code != 0) {
        return_code = errno;
        fprintf(stderr, "failed to get entry: %s\n", strerror(return_code));
        goto clean_up;
    }

    /* No need to parse key - already provided by user */

    /* Parse value */
    return_code = parse_table_value(ctx, entry, value_buffer);
    if (return_code != NO_ERROR)
        fprintf(stderr, "failed to parse entry: %s\n", strerror(return_code));

clean_up:
    if (key_buffer != NULL)
        free(key_buffer);
    if (key_mask_buffer != NULL)
        free(key_mask_buffer);
    if (value_buffer != NULL)
        free(value_buffer);

    if (ctx->is_ternary)
        ternary_table_close_tuple(ctx);

    return return_code;
}

int psabpf_table_entry_get_next(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    if (ctx == NULL || entry == NULL)
        return EINVAL;

    return NO_ERROR;
}

int psabpf_table_entry_get_default_entry(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    if (ctx == NULL || entry == NULL)
        return EINVAL;

    return NO_ERROR;
}
