#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <linux/bpf.h>
#include <linux/btf.h>

#include "../include/psabpf.h"
#include "../include/bpf_defs.h"
#include "btf.h"

#define COUNTER_PACKETS_OR_BYTES_STRUCT_ENTRIES  1
#define COUNTER_PACKETS_AND_BYTES_STRUCT_ENTRIES 2

static int str_ends_with(const char *str, const char *suffix)
{
    size_t len_str = strlen(str);
    size_t len_suffix = strlen(suffix);
    if (len_suffix >  len_str)
        return 0;
    return strncmp(str + len_str - len_suffix, suffix, len_suffix) == 0;
}

/* Data len must be aligned to 4B */
static void mem_bitwise_and(uint32_t *dst, uint32_t *mask, size_t len)
{
    for (int i = 0; i < len / 4; i++) {
        *dst = (uint32_t) ((*dst) & (*mask));
        ++dst; ++mask;
    }
}

void psabpf_table_entry_ctx_init(psabpf_table_entry_ctx_t *ctx)
{
    if (ctx == NULL)
        return;
    memset(ctx, 0, sizeof(psabpf_table_entry_ctx_t));

    /* 0 is a valid file descriptor */
    ctx->table_fd = -1;
    ctx->associated_prog = -1;
    ctx->prefixes_fd = -1;
    ctx->tuple_map_fd = -1;
}

static void close_object_fd(int *fd)
{
    if (*fd >= 0)
        close(*fd);
    *fd = -1;
}

void psabpf_table_entry_ctx_free(psabpf_table_entry_ctx_t *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->btf)
        btf__free(ctx->btf);
    ctx->btf = NULL;

    close_object_fd(&(ctx->table_fd));
    close_object_fd(&(ctx->prefixes_fd));
    close_object_fd(&(ctx->tuple_map_fd));
    close_object_fd(&(ctx->associated_prog));
}

static int try_load_btf(psabpf_table_entry_ctx_t *ctx, const char *program_name)
{
    ctx->associated_prog = bpf_obj_get(program_name);
    if (ctx->associated_prog < 0)
        return ENOENT;

    struct bpf_prog_info prog_info = {};
    unsigned len = sizeof(struct bpf_prog_info);
    int error = bpf_obj_get_info_by_fd(ctx->associated_prog, &prog_info, &len);
    if (error)
        goto free_program;

    error = btf__get_from_id(prog_info.btf_id, (struct btf **) &(ctx->btf));
    if (ctx->btf == NULL || error != 0)
        goto free_btf;

    return NO_ERROR;

free_btf:
    if (ctx->btf != NULL)
        btf__free(ctx->btf);
    ctx->btf = NULL;

free_program:
    if (ctx->associated_prog >= 0)
        close(ctx->associated_prog);
    ctx->associated_prog = -1;

    return ENOENT;
}

static int load_btf(psabpf_context_t *psabpf_ctx, psabpf_table_entry_ctx_t *ctx)
{
    if (ctx->btf != NULL)
        return NO_ERROR;

    char program_file_name[256];
    const char *programs_to_search[] = { TC_INGRESS_PROG, XDP_INGRESS_PROG, TC_EGRESS_PROG };
    int number_of_programs = sizeof(programs_to_search) / sizeof(programs_to_search[0]);

    for (int i = 0; i < number_of_programs; i++) {
        snprintf(program_file_name, sizeof(program_file_name), "%s/%s%u/%s",
                 BPF_FS, PIPELINE_PREFIX, psabpf_context_get_pipeline(psabpf_ctx), programs_to_search[i]);
        if (try_load_btf(ctx, program_file_name) == NO_ERROR)
            break;
    }
    if (ctx->btf == NULL)
        return ENOENT;

    return NO_ERROR;
}

static int open_bpf_map(psabpf_table_entry_ctx_t *ctx, const char *name, const char *base_path, int *fd, uint32_t *key_size,
                        uint32_t *value_size, uint32_t *map_type, uint32_t *btf_type_id, uint32_t *max_entries)
{
    char buffer[257];
    int errno_val;

    snprintf(buffer, sizeof(buffer), "%s/%s", base_path, name);
    *fd = bpf_obj_get(buffer);
    if (*fd < 0)
        return errno;

    /* get key/value size */
    struct bpf_map_info info = {};
    uint32_t len = sizeof(info);
    errno_val = bpf_obj_get_info_by_fd(*fd, &info, &len);
    if (errno_val) {
        errno_val = errno;
        fprintf(stderr, "can't get info for table %s: %s\n", name, strerror(errno_val));
        return errno_val;
    }
    if (map_type != NULL)
        *map_type = info.type;
    *key_size = info.key_size;
    *value_size = info.value_size;
    if (max_entries != NULL)
        *max_entries = info.max_entries;

    /* Find entry in BTF for our map */
    if (btf_type_id != NULL) {
        snprintf(buffer, sizeof(buffer), ".maps.%s", name);
        *btf_type_id = psabtf_get_type_id_by_name(ctx->btf, buffer);
        if (*btf_type_id == 0)
            fprintf(stderr, "can't get BTF info for %s\n", name);
    }

    return NO_ERROR;
}

static int open_ternary_table(psabpf_table_entry_ctx_t *ctx, const char *name, const char *base_path)
{
    int ret;
    char derived_name[256];

    snprintf(derived_name, sizeof(derived_name), "%s_prefixes", name);
    ret = open_bpf_map(ctx, derived_name, base_path, &(ctx->prefixes_fd), &(ctx->prefixes_key_size),
                       &(ctx->prefixes_value_size), NULL, &(ctx->prefixes_btf_type_id), NULL);
    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't open map %s: %s\n", derived_name, strerror(ret));
        return ret;
    }

    snprintf(derived_name, sizeof(derived_name), "%s_tuples_map", name);
    ret = open_bpf_map(ctx, derived_name, base_path, &(ctx->tuple_map_fd), &(ctx->tuple_map_key_size),
                       &(ctx->tuple_map_value_size), NULL, NULL, NULL);
    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't open map %s: %s\n", derived_name, strerror(ret));
        return ret;
    }

    snprintf(derived_name, sizeof(derived_name), "%s_tuple", name);
    ret = open_bpf_map(ctx, derived_name, base_path, &(ctx->table_fd), &(ctx->key_size), &(ctx->value_size),
                       &(ctx->table_type), &(ctx->btf_type_id), &(ctx->tuple_max_entries));
    close_object_fd(&(ctx->table_fd));  /* We need only metadata from this map */
    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't open map %s: %s\n", derived_name, strerror(ret));
        return ret;
    }

    ctx->is_ternary = true;

    return NO_ERROR;
}

int psabpf_table_entry_ctx_tblname(psabpf_context_t *psabpf_ctx, psabpf_table_entry_ctx_t *ctx, const char *name)
{
    if (ctx == NULL)
        return EPERM;

    char base_path[256];
    snprintf(base_path, sizeof(base_path), "%s/%s%u/maps",
             BPF_FS, PIPELINE_PREFIX, psabpf_context_get_pipeline(psabpf_ctx));
    snprintf(ctx->base_name, sizeof(ctx->base_name), "%s", name);

    /* get the BTF, it is optional so print only warning */
    if (load_btf(psabpf_ctx, ctx) != NO_ERROR)
        fprintf(stderr, "warning: couldn't find BTF info\n");

    int ret = open_bpf_map(ctx, name, base_path, &(ctx->table_fd), &(ctx->key_size), &(ctx->value_size),
                           &(ctx->table_type), &(ctx->btf_type_id), NULL);

    /* if map does not exist, try the ternary table */
    if (ret == ENOENT)
        ret = open_ternary_table(ctx, name, base_path);

    if (ret != NO_ERROR) {
        fprintf(stderr, "couldn't open table %s: %s\n", name, strerror(ret));
        return ret;
    }

    return NO_ERROR;
}

void psabpf_table_entry_ctx_mark_indirect(psabpf_table_entry_ctx_t *ctx)
{
    ctx->is_indirect = true;
}

void psabpf_table_entry_init(psabpf_table_entry_t *entry)
{
    if (entry == NULL)
        return;
    memset(entry, 0, sizeof(psabpf_table_entry_t));
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

void psabpf_table_entry_action(psabpf_table_entry_t *entry, psabpf_action_t *act)
{
    if (entry == NULL || act == NULL)
        return;

    if (entry->action != NULL)
        return;

    entry->action = malloc(sizeof(psabpf_action_t));
    if (entry->action == NULL)
        return;
    memcpy(entry->action, act, sizeof(psabpf_action_t));

    /* stole action data */
    act->params = NULL;
    act->n_params = 0;
}

/* only for ternary */
void psabpf_table_entry_priority(psabpf_table_entry_t *entry, const uint32_t priority)
{
    entry->priority = priority;
}

void psabpf_matchkey_init(psabpf_match_key_t *mk)
{
    if (mk == NULL)
        return;
    memset(mk, 0, sizeof(psabpf_match_key_t));
}

void psabpf_matchkey_free(psabpf_match_key_t *mk)
{
    if (mk == NULL)
        return;

    if (mk->data != NULL)
        free(mk->data);
    mk->data = NULL;

    if (mk->type == PSABPF_TERNARY) {
        if (mk->u.ternary.mask != NULL)
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
    if (mk == NULL)
        return EFAULT;
    if (mk->data != NULL)
        return EEXIST;

    mk->data = malloc(size);
    if (mk->data == NULL)
        return ENOMEM;
    memcpy(mk->data, data, size);
    mk->key_size = size;

    return NO_ERROR;
}

/* only for lpm */
int psabpf_matchkey_prefix(psabpf_match_key_t *mk, uint32_t prefix)
{
    if (mk == NULL)
        return ENODATA;
    if (mk->type != PSABPF_LPM)
        return EINVAL;

    mk->u.lpm.prefix_len = prefix;

    return NO_ERROR;
}

/* only for ternary */
int psabpf_matchkey_mask(psabpf_match_key_t *mk, const char *mask, size_t size)
{
    if (mk == NULL || mask == NULL)
        return ENODATA;
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

/* only for 'range' match */
int psabpf_matchkey_start(psabpf_match_key_t *mk, uint64_t start)
{
    return NO_ERROR;
}

/* only for 'range' match */
int psabpf_matchkey_end(psabpf_match_key_t *mk, uint64_t end)
{
    return NO_ERROR;
}

int psabpf_action_param_create(psabpf_action_param_t *param, const char *data, size_t size)
{
    param->is_group_reference = false;
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
    if (param->data != NULL)
        free(param->data);
    param->data = NULL;
}

void psabpf_action_param_mark_group_reference(psabpf_action_param_t *param)
{
    param->is_group_reference = true;
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

    for (int i = 0; i < action->n_params; i++) {
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

    /* stole data */
    param->data = NULL;

    action->n_params += 1;

    return NO_ERROR;
}

enum write_flags {
    WRITE_HOST_ORDER = 0,
    WRITE_NETWORK_ORDER
};

static int write_buffer_btf(char * buffer, size_t buffer_len, size_t offset,
                            void * data, size_t data_len, psabpf_table_entry_ctx_t *ctx,
                            uint32_t dst_type_id, const char *dst_type, enum write_flags flags)
{
    size_t data_type_len = psabtf_get_type_size_by_id(ctx->btf, dst_type_id);

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
    size_t bytes_to_write = ctx->key_size;
    uint32_t *lpm_prefix = NULL;

    if (ctx->table_type == BPF_MAP_TYPE_LPM_TRIE) {
        const size_t prefix_size = 4;
        lpm_prefix = (uint32_t *) buffer;
        if (ctx->key_size < prefix_size) {
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

        if (ctx->table_type == BPF_MAP_TYPE_LPM_TRIE && mk->type == PSABPF_LPM) {
            /* copy data in network byte order (in reverse order) */
            for (size_t k = 0; k < mk->key_size; ++k)
                buffer[k] = ((char *) (mk->data))[mk->key_size - k - 1];
        } else {
            memcpy(buffer, mk->data, mk->key_size);
        }

        /* write prefix length */
        if (ctx->table_type == BPF_MAP_TYPE_LPM_TRIE && mk->type == PSABPF_LPM) {
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

static int fill_key_btf_info(char * buffer, psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    uint32_t key_type_id = psabtf_get_member_type_id_by_name(ctx->btf, ctx->btf_type_id, "key");
    if (key_type_id == 0)
        return EAGAIN;
    const struct btf_type *key_type = psabtf_get_type_by_id(ctx->btf, key_type_id);
    if (key_type == NULL)
        return EAGAIN;

    if (btf_kind(key_type) == BTF_KIND_INT) {
        if (entry->n_keys != 1) {
            fprintf(stderr, "expected 1 key\n");
            return EAGAIN;
        }
        if (entry->match_keys[0]->key_size > ctx->key_size) {
            fprintf(stderr, "too much data in key\n");
            return EPERM;  /* byte by byte mode will not fix this */
        }
        memcpy(buffer, entry->match_keys[0]->data, entry->match_keys[0]->key_size);
    } else if (btf_kind(key_type) == BTF_KIND_STRUCT) {
        const struct btf_member *member = btf_members(key_type);
        int entries = btf_vlen(key_type);
        int expected_entries = entries;

        if (ctx->table_type == BPF_MAP_TYPE_LPM_TRIE)
            --expected_entries;  /* omit prefix length */
        if (entry->n_keys != expected_entries) {
            fprintf(stderr, "expected %d keys, got %zu\n", expected_entries, entry->n_keys);
            return EAGAIN;
        }

        for (int member_idx = 0, key_idx = 0; member_idx < entries; member_idx++, member++) {
            if (member_idx == 0 && ctx->table_type == BPF_MAP_TYPE_LPM_TRIE)
                continue;  /* skip prefix length */

            /* assume that every field is byte aligned */
            unsigned offset = btf_member_bit_offset(key_type, member_idx) / 8;
            psabpf_match_key_t *mk = entry->match_keys[key_idx];
            int ret = 0, flags = WRITE_HOST_ORDER;

            if (ctx->table_type == BPF_MAP_TYPE_LPM_TRIE && mk->type == PSABPF_LPM)
                flags = WRITE_NETWORK_ORDER;
            ret = write_buffer_btf(buffer, ctx->key_size, offset, mk->data, mk->key_size,
                                   ctx, member->type, "key", flags);
            if (ret != NO_ERROR)
                return ret;

            /* write prefix value for LPM field */
            if (ctx->table_type == BPF_MAP_TYPE_LPM_TRIE && mk->type == PSABPF_LPM) {
                uint32_t prefix_value = offset * 8 + mk->u.lpm.prefix_len - 32;
                psabtf_struct_member_md_t prefix_md;
                if (psabtf_get_member_md_by_index(ctx->btf, key_type_id, 0, &prefix_md) != NO_ERROR)
                    return EAGAIN;
                ret = write_buffer_btf(buffer, ctx->key_size, prefix_md.bit_offset / 8,
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
    size_t bytes_to_write = ctx->value_size;

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

static int fill_action_id(char * buffer, psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry,
                          uint32_t value_type_id, const struct btf_type *value_type)
{
    psabtf_struct_member_md_t action_md = {};
    if (psabtf_get_member_md_by_name(ctx->btf, value_type_id, "action", &action_md) != NO_ERROR) {
        fprintf(stderr, "action id entry not found\n");
        return ENOENT;
    }
    return write_buffer_btf(buffer, ctx->value_size, action_md.bit_offset / 8,
                            &(entry->action->action_id), sizeof(entry->action->action_id),
                            ctx, action_md.effective_type_id, "action id", WRITE_HOST_ORDER);
}

static int fill_priority(char * buffer, psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry,
                         uint32_t value_type_id, const struct btf_type *value_type)
{
    if (ctx->is_ternary == false)
        return NO_ERROR;

    psabtf_struct_member_md_t priority_md = {};
    if (psabtf_get_member_md_by_name(ctx->btf, value_type_id, "priority", &priority_md) != NO_ERROR) {
        fprintf(stderr, "priority entry not found\n");
        return ENOENT;
    }
    return write_buffer_btf(buffer, ctx->value_size, priority_md.bit_offset / 8,
                            &(entry->priority), sizeof(entry->priority),
                            ctx, priority_md.effective_type_id, "priority", WRITE_HOST_ORDER);
}

static int fill_action_data(char * buffer, psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry,
                            uint32_t value_type_id, const struct btf_type *value_type)
{
    size_t base_offset, offset;
    int ret;

    /* find union with action data */
    psabtf_struct_member_md_t action_union_md = {};
    if (psabtf_get_member_md_by_name(ctx->btf, value_type_id, "u", &action_union_md) != NO_ERROR) {
        fprintf(stderr, "actions data structure not found\n");
        return ENOENT;
    }
    const struct btf_type * union_type = psabtf_get_type_by_id(ctx->btf, action_union_md.effective_type_id);
    base_offset = action_union_md.bit_offset / 8;

    /* find action data structure in the union */
    psabtf_struct_member_md_t action_data_md = {};
    if (psabtf_get_member_md_by_index(ctx->btf, action_union_md.effective_type_id,
                                      entry->action->action_id, &action_data_md) != NO_ERROR) {
        fprintf(stderr, "action with id %u does not exist\n", entry->action->action_id);
        return EPERM;  /* not fixable, invalid action ID */
    }
    /* to be sure of offset, take into account offset of action data structure in the union */
    base_offset = base_offset + action_data_md.bit_offset / 8;
    const struct btf_type * data_type = psabtf_get_type_by_id(ctx->btf, action_data_md.effective_type_id);

    /* fill action data */
    int entries = btf_vlen(data_type);
    if (entry->action->n_params != entries) {
        fprintf(stderr, "expected %d action parameters, got %zu\n",
                entries, entry->action->n_params);
        return EAGAIN;
    }
    const struct btf_member *member = btf_members(data_type);
    for (int i = 0; i < entries; i++, member++) {
        offset = btf_member_bit_offset(data_type, i) / 8;
        ret = write_buffer_btf(buffer, ctx->value_size, base_offset + offset,
                               entry->action->params[i].data, entry->action->params[i].len,
                               ctx, member->type, "value", WRITE_HOST_ORDER);
        if (ret != NO_ERROR)
            return ret;
    }

    return NO_ERROR;
}

static int fill_action_references(char * buffer, psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry,
                                  uint32_t value_type_id, const struct btf_type *value_type)
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
        const struct btf_type * member_type = psabtf_get_type_by_id(ctx->btf, member->type);
        const char * member_name = btf__name_by_offset(ctx->btf, member->name_off);

        /* skip errors, non-int members and reserved names */
        if (member_name == NULL || btf_kind(member_type) != BTF_KIND_INT)
            continue;
        if (strcmp(member_name, "priority") == 0 || strcmp(member_name, "action") == 0)
            continue;

        if (str_ends_with(member_name, "_is_group_ref")) {
            offset = btf_member_bit_offset(value_type, i) / 8;
            ret = write_buffer_btf(buffer, ctx->value_size, offset,
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
        ret = write_buffer_btf(buffer, ctx->value_size, offset, current_data->data,
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
    size_t offset, base_offset;
    int ret;

    uint32_t value_type_id = psabtf_get_member_type_id_by_name(ctx->btf, ctx->btf_type_id, "value");
    if (value_type_id == 0)
        return EAGAIN;
    const struct btf_type *value_type = psabtf_get_type_by_id(ctx->btf, value_type_id);
    if (value_type == NULL)
        return EAGAIN;

    if (btf_kind(value_type) != BTF_KIND_STRUCT) {
        fprintf(stderr, "expected struct as a map value\n");
        return EAGAIN;
    }

    if (ctx->is_indirect == false) {
        ret = fill_action_id(buffer, ctx, entry, value_type_id, value_type);
        if (ret != NO_ERROR)
            return ret;

        ret = fill_action_data(buffer, ctx, entry, value_type_id, value_type);
        if (ret != NO_ERROR)
            return ret;
    } else {
        ret = fill_action_references(buffer, ctx, entry, value_type_id, value_type);
        if (ret != NO_ERROR)
            return ret;
    }

    ret = fill_priority(buffer, ctx, entry, value_type_id, value_type);
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
    size_t bytes_to_write = ctx->prefixes_key_size;
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
    uint32_t key_type_id = psabtf_get_member_type_id_by_name(ctx->btf, ctx->btf_type_id, "key");
    if (key_type_id == 0)
        return EAGAIN;

    const struct btf_type *key_type = psabtf_get_type_by_id(ctx->btf, key_type_id);
    if (key_type == NULL)
        return EAGAIN;
    if (btf_kind(key_type) != BTF_KIND_STRUCT)
        return EAGAIN;

    const struct btf_member *member = btf_members(key_type);
    int entries = btf_vlen(key_type);
    if (entry->n_keys != entries) {
        fprintf(stderr, "expected %d keys, got %zu\n", entries, entry->n_keys);
        return EAGAIN;
    }

    /* Prepare temporary mask buffer for current field. Every field size <= key_size */
    char * tmp_mask = malloc(ctx->key_size);
    if (tmp_mask == NULL)
        return ENOMEM;

    int ret = EAGAIN;
    for (int i = 0; i < entries; i++, member++) {
        psabpf_match_key_t *mk = entry->match_keys[i];
        unsigned offset = btf_member_bit_offset(key_type, i) / 8;
        size_t size = psabtf_get_type_size_by_id(ctx->btf, member->type);

        ret = EAGAIN;
        memset(tmp_mask, 0, ctx->key_size);
        if (mk->type == PSABPF_EXACT) {
            if (size > ctx->key_size)
                break;
            memset(tmp_mask, 0xFF, size);
            ret = write_buffer_btf(buffer, ctx->prefixes_key_size, offset, tmp_mask, size,
                                   ctx, member->type, "exact mask key", WRITE_HOST_ORDER);
        } else if (mk->type == PSABPF_LPM) {
            ret = lpm_prefix_to_mask(tmp_mask, size, mk->u.lpm.prefix_len, size);
            if (ret != NO_ERROR) {
                ret = EAGAIN;
                break;
            }
            ret = write_buffer_btf(buffer, ctx->prefixes_key_size, offset, tmp_mask, size,
                                   ctx, member->type, "lpm mask key", WRITE_HOST_ORDER);
        } else if (mk->type == PSABPF_TERNARY) {
            ret = write_buffer_btf(buffer, ctx->prefixes_key_size, offset, mk->u.ternary.mask,
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
    if (ctx->btf != NULL && ctx->btf_type_id != 0) {
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

static bool member_is_counter(psabpf_table_entry_ctx_t *ctx, const struct btf_member *member)
{
    const struct btf_type *type = psabtf_get_type_by_id(ctx->btf, member->type);
    if (btf_kind(type) != BTF_KIND_STRUCT)
        return false;
    unsigned entries = btf_vlen(type);
    if (entries != COUNTER_PACKETS_OR_BYTES_STRUCT_ENTRIES &&
        entries != COUNTER_PACKETS_AND_BYTES_STRUCT_ENTRIES)
        return false;

    /* Allowed field names: "packets", "bytes" */
    const struct btf_member *m = btf_members(type);
    for (int i = 0; i < entries; i++, m++) {
        const char *field_name = btf__name_by_offset(ctx->btf, m->name_off);
        if (field_name == NULL)
            return false;
        if (strcmp(field_name, "bytes") == 0 ||
            strcmp(field_name, "packets") == 0)
            continue;

        /* Unknown field name */
        return false;
    }

    return true;
}

static int handle_counters(const char *key, char *value_buffer,
                           psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    if (ctx->is_indirect || ctx->btf == NULL || ctx->btf_type_id == 0) {
        fprintf(stderr, "unable to handle counters; resetting them to 0 if exist\n");
        return NO_ERROR;
    }

    psabtf_struct_member_md_t value_md = {};
    if (psabtf_get_member_md_by_name(ctx->btf, ctx->btf_type_id, "value", &value_md) != NO_ERROR)
        return ENOENT;

    const struct btf_type *value_type = psabtf_get_type_by_id(ctx->btf, value_md.effective_type_id);
    if (value_type == NULL)
        return EPERM;
    if (btf_kind(value_type) != BTF_KIND_STRUCT)
        return EPERM;

    unsigned entries = btf_vlen(value_type);
    const struct btf_member *member = btf_members(value_type);

    /* Optimization: check if we have any counter
     * Rationale: do not make system call to get old value of counters if there is no counters */
    bool has_counter = false;
    for (int i = 0; i < entries; i++, member++) {
        if (member_is_counter(ctx, member)) {
            has_counter = true;
            break;
        }
    }
    if (!has_counter)
        return NO_ERROR;

    /* Read current counters value */
    char * reference_buffer = malloc(ctx->value_size);
    if (reference_buffer == NULL)
        return ENOMEM;
    int err = bpf_map_lookup_elem(ctx->table_fd, key, reference_buffer);
    if (err != 0) {
        fprintf(stderr, "entry with counters not found\n");
        goto clean_up;
    }

    /* Preserve counters value */
    member = btf_members(value_type);
    for (int i = 0; i < entries; i++, member++) {
        if (!member_is_counter(ctx, member))
            continue;

        size_t offset = btf_member_bit_offset(value_type, i) / 8;
        size_t size = psabtf_get_type_size_by_id(ctx->btf, member->type);
        if (offset + size > ctx->value_size) {
            fprintf(stderr, "can't write counter at offset %zu and size %zu (entry size %u)\n",
                    offset, size, ctx->value_size);
            err = EPERM;
            goto clean_up;
        }
        memcpy(value_buffer + offset, reference_buffer + offset, size);
    }

clean_up:
    free(reference_buffer);
    return err;
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
    md->next_mask_size = ctx->key_size;
    md->has_next_size = sizeof(uint8_t);
    /* Lets guess offsets (they will be fixed with BTF if available) */
    md->tuple_id_offset = 0;  /* at the beginning of the structure */
    md->next_mask_offset = ctx->key_size > 4 ? 8 : 4;  /* after tuple_id field */
    md->has_next_offset = md->next_mask_offset + md->next_mask_size;  /* after next_mask field */

    if (ctx->btf == NULL || ctx->prefixes_btf_type_id == 0)
        return NO_ERROR;

    uint32_t type_id = psabtf_get_member_type_id_by_name(ctx->btf, ctx->prefixes_btf_type_id, "value");
    if (type_id == 0)
        return EPERM;

    /* tuple id */
    if (psabtf_get_member_md_by_name(ctx->btf, type_id, "tuple_id", &member) != NO_ERROR)
        return EPERM;
    md->tuple_id_size = psabtf_get_type_size_by_id(ctx->btf, member.effective_type_id);
    md->tuple_id_offset = member.bit_offset / 8;

    /* next mask */
    if (psabtf_get_member_md_by_name(ctx->btf, type_id, "next_tuple_mask", &member) != NO_ERROR)
        return EPERM;
    md->next_mask_size = psabtf_get_type_size_by_id(ctx->btf, member.effective_type_id);
    md->next_mask_offset = member.bit_offset / 8;

    /* has next */
    if (psabtf_get_member_md_by_name(ctx->btf, type_id, "has_next", &member) != NO_ERROR)
        return EPERM;
    md->has_next_size = psabtf_get_type_size_by_id(ctx->btf, member.effective_type_id);
    md->has_next_offset = member.bit_offset / 8;

    /* validate size and offset */
    if (md->tuple_id_offset + md->tuple_id_size > ctx->prefixes_value_size ||
        md->next_mask_offset + md->next_mask_size > ctx->prefixes_value_size ||
        md->has_next_offset + md->has_next_size > ctx->prefixes_value_size ||
        md->next_mask_size != ctx->key_size) {
        fprintf(stderr, "BUG: invalid size or offset in the mask\n");
        return EPERM;
    }

    return NO_ERROR;
}

static int add_ternary_table_prefix(char *new_prefix, char *prefix_value,
                                    psabpf_table_entry_ctx_t *ctx, uint64_t bpf_flags)
{
    int err = NO_ERROR;
    uint32_t tuple_id = 0;
    struct ternary_table_prefix_metadata prefix_md;

    if (get_ternary_table_prefix_md(ctx, &prefix_md) != NO_ERROR) {
        fprintf(stderr, "failed to obtain offsets and sizes of prefix\n");
        return EPERM;
    }

    char *key = malloc(ctx->prefixes_key_size);
    char *value = malloc(ctx->prefixes_value_size);
    if (key == NULL || value == NULL) {
        fprintf(stderr, "not enough memory\n");
        err = ENOMEM;
        goto clean_up;
    }

    /* Process head */
    memset(key, 0, ctx->prefixes_key_size);
    err = bpf_map_lookup_elem(ctx->prefixes_fd, key, value);
    if (err != 0) {
        /* Construct head, it will be added later */
        memset(value, 0, ctx->prefixes_value_size);
        *((uint32_t *) (value + prefix_md.tuple_id_offset)) = tuple_id;
    }

    /* Iterate over every prefix to the last one */
    while (true) {
        uint8_t has_next = *((uint8_t *) (value + prefix_md.has_next_offset));
        if (has_next == 0)
            break;

        /* Get next prefix */
        memcpy(key, value + prefix_md.next_mask_offset, prefix_md.next_mask_size);
        err = bpf_map_lookup_elem(ctx->prefixes_fd, key, value);
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
    memset(prefix_value, 0, ctx->prefixes_value_size);
    *((uint32_t *) (prefix_value + prefix_md.tuple_id_offset)) = ++tuple_id;
    err = bpf_map_update_elem(ctx->prefixes_fd, new_prefix, prefix_value, BPF_NOEXIST);
    if (err != 0)
        goto clean_up;

    /* Update previous node */
    memcpy(value + prefix_md.next_mask_offset, new_prefix, prefix_md.next_mask_size);
    *((uint8_t *) (value + prefix_md.has_next_offset)) = 1;
    err = bpf_map_update_elem(ctx->prefixes_fd, key, value, BPF_ANY);
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
    char map_name[264];
    snprintf(map_name, sizeof(map_name), "%s_tuple_%u", ctx->base_name, tuple_id);

    struct bpf_create_map_attr attr = {
            .key_size = ctx->key_size,
            .value_size = ctx->value_size,
            .max_entries = ctx->tuple_max_entries,
            .map_type = ctx->table_type,
            .name = map_name,
    };
    ctx->table_fd = bpf_create_map_xattr(&attr);
    if (ctx->table_fd < 0) {
        err = errno;
        fprintf(stderr, "failed to create tuple %u: %s\n", tuple_id, strerror(err));
        return err;
    }

    /* add tuple to tuples map */
    err = bpf_map_update_elem(ctx->tuple_map_fd, &tuple_id, &(ctx->table_fd), 0);
    if (err != 0) {
        err = errno;
        fprintf(stderr, "failed to add tuple %u: %s\n", tuple_id, strerror(err));
        close_object_fd(&(ctx->table_fd));
    }

    return err;
}

static int ternary_table_open_tuple(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry,
                                    char **key_mask, uint64_t bpf_flags)
{
    if (ctx->prefixes_fd < 0 || ctx->tuple_map_fd < 0 || ctx->table_fd >= 0) {
        fprintf(stderr, "ternary table not properly opened. BUG?\n");
        return EINVAL;
    }
    if (ctx->key_size != ctx->prefixes_key_size) {
        fprintf(stderr, "key and its mask have different length. BUG?\n");
        return EINVAL;
    }
    if (ctx->tuple_map_key_size != 4 || ctx->tuple_map_value_size != 4) {
        fprintf(stderr, "key/value size of tuples map have to be 4B.\n");
        return EINVAL;
    }

    int err = NO_ERROR;
    char *value_mask = malloc(ctx->prefixes_value_size);
    *key_mask = malloc(ctx->prefixes_key_size);

    if (*key_mask == NULL || value_mask == NULL) {
        fprintf(stderr, "not enough memory\n");
        err = ENOMEM;
        goto clean_up;
    }
    memset(*key_mask, 0, ctx->prefixes_key_size);
    memset(value_mask, 0, ctx->prefixes_value_size);

    err = construct_buffer(*key_mask, ctx->prefixes_key_size, ctx, entry,
                           fill_key_mask_btf, fill_key_mask_byte_by_byte);
    if (err != NO_ERROR)
        goto clean_up;

    /* prefixes head protection - check whether mask is different from all 0 */
    bool mask_is_valid = false;
    for (int i = 0; i < ctx->prefixes_key_size; i++) {
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

    err = bpf_map_lookup_elem(ctx->prefixes_fd, *key_mask, value_mask);
    /* It is not allowed to add new prefix when updating existing entry */
    if (err != 0 && bpf_flags != BPF_EXIST) {
        err = add_ternary_table_prefix(*key_mask, value_mask, ctx, bpf_flags);
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

    err = bpf_map_lookup_elem(ctx->tuple_map_fd, &tuple_id, &inner_map_id);
    if (err == 0) {
        ctx->table_fd = bpf_map_get_fd_by_id(inner_map_id);
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

static void post_ternary_table_write(psabpf_table_entry_ctx_t *ctx)
{
    /* Allow for reuse table context with the same table but other tuple (inner map). */
    if (ctx->is_ternary)
        close_object_fd(&(ctx->table_fd));
}

int psabpf_table_entry_write(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry, uint64_t bpf_flags)
{
    char *key_buffer = NULL;
    char *key_mask_buffer = NULL;
    char *value_buffer = NULL;
    int return_code = NO_ERROR;

    if (ctx->is_ternary) {
        return_code = ternary_table_open_tuple(ctx, entry, &key_mask_buffer, bpf_flags);
        if (return_code != NO_ERROR)
            goto clean_up;
    }

    if (ctx->table_fd < 0) {
        fprintf(stderr, "can't add entry: table not opened\n");
        return EBADF;
    }
    if (ctx->key_size == 0 || ctx->value_size == 0) {
        fprintf(stderr, "zero-size key or value is not supported\n");
        return ENOTSUP;
    }
    if (entry->action == NULL) {
        fprintf(stderr, "missing action specification\n");
        return ENODATA;
    }

    /* prepare buffers for map key/value */
    key_buffer = malloc(ctx->key_size);
    value_buffer = malloc(ctx->value_size);
    if (key_buffer == NULL || value_buffer == NULL) {
        fprintf(stderr, "not enough memory\n");
        return_code = ENOMEM;
        goto clean_up;
    }

    return_code = construct_buffer(key_buffer, ctx->key_size, ctx, entry,
                                   fill_key_btf_info, fill_key_byte_by_byte);
    if (return_code != NO_ERROR) {
        fprintf(stderr, "failed to construct key\n");
        goto clean_up;
    }

    return_code = construct_buffer(value_buffer, ctx->value_size, ctx, entry,
                                   fill_value_btf_info, fill_value_byte_by_byte);
    if (return_code != NO_ERROR) {
        fprintf(stderr, "failed to construct value\n");
        goto clean_up;
    }

    if (ctx->is_ternary == true && key_mask_buffer != NULL)
        mem_bitwise_and((uint32_t *) key_buffer, (uint32_t *) key_mask_buffer, ctx->key_size);

    /* Handle direct objects */
    if (bpf_flags == BPF_EXIST) {
        return_code = handle_counters(key_buffer, value_buffer, ctx, entry);
        if (return_code != NO_ERROR) {
            fprintf(stderr, "failed to handle counters\n");
            goto clean_up;
        }
    }

    /* update map */
    if (ctx->table_type == BPF_MAP_TYPE_ARRAY)
        bpf_flags = BPF_ANY;
    return_code = bpf_map_update_elem(ctx->table_fd, key_buffer, value_buffer, bpf_flags);
    if (return_code != 0) {
        return_code = errno;
        fprintf(stderr, "failed to set up entry: %s\n", strerror(errno));
    }

clean_up:
    if (key_buffer != NULL)
        free(key_buffer);
    if (key_mask_buffer != NULL)
        free(key_mask_buffer);
    if (value_buffer != NULL)
        free(value_buffer);

    if (ctx->is_ternary)
        post_ternary_table_write(ctx);

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

        /* Ignore error(s) from bpf_map_delete_elem(). In some cases key may exists
         * but entry not exists (e.g. array map in map). So in any case we have to
         * iterate over all keys and try delete it. */
        bpf_map_delete_elem(fd, key);
    } while (bpf_map_get_next_key(fd, key, next_key) == 0);

clean_up:
    if (key)
        free(key);
    if (next_key)
        free(next_key);
    return error_code;
}

static int prepare_ternary_table_delete(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry, char **key_mask)
{
    if (entry->n_keys != 0)
        return ternary_table_open_tuple(ctx, entry, key_mask, BPF_EXIST);

    delete_all_table_entries(ctx->prefixes_fd, ctx->prefixes_key_size);
    fprintf(stderr, "removing entries from tuples_map, this may take a while\n");
    delete_all_table_entries(ctx->tuple_map_fd, ctx->tuple_map_key_size);

    /* Unpinning inner maps for our table is not required
     * because they are not pinned by this tool. */

    return NO_ERROR;
}

static int ternary_table_remove_prefix(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry, const char *key_mask)
{
    int err = NO_ERROR;
    char *prev_key_mask = malloc(ctx->prefixes_key_size);
    char *prev_value_mask = malloc(ctx->prefixes_value_size);
    char *value_mask = malloc(ctx->prefixes_value_size);

    if (prev_key_mask == NULL || prev_value_mask == NULL || value_mask == NULL) {
        fprintf(stderr, "not enough memory\n");
        err = ENOMEM;
        goto clean_up;
    }

    if (bpf_map_lookup_elem(ctx->prefixes_fd, key_mask, value_mask) != 0) {
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
    memset(prev_key_mask, 0, ctx->prefixes_key_size);
    err = bpf_map_lookup_elem(ctx->prefixes_fd, prev_key_mask, prev_value_mask);
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
        if (bpf_map_lookup_elem(ctx->prefixes_fd, prev_key_mask, prev_value_mask) != 0)
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

        err = bpf_map_update_elem(ctx->prefixes_fd, prev_key_mask, prev_value_mask, BPF_EXIST);
        if (err != 0) {
            err = errno;
            fprintf(stderr, "failed to update previous prefix: %s\n", strerror(err));
            goto clean_up;
        }
    }

    /* there are no prefixes that points to removing prefix, so it can be safely removed now */
    if (bpf_map_delete_elem(ctx->prefixes_fd, key_mask) != 0)
        fprintf(stderr, "warning: failed to remove prefix from prefixes list\n");

    /* also remove tuple from tuple_map */
    uint32_t tuple_id = *((uint32_t *) (value_mask + prefix_md.tuple_id_offset));
    if (bpf_map_delete_elem(ctx->tuple_map_fd, &tuple_id) != 0)
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

static int post_ternary_table_delete(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry, const char *key_mask)
{
    if (ctx->is_ternary == false || ctx->table_fd < 0)
        return NO_ERROR;
    if (key_mask == NULL)
        return ENODATA;

    int err = NO_ERROR;
    char *tuple_next_key = malloc(ctx->key_size);

    if (tuple_next_key == NULL) {
        fprintf(stderr, "not enough memory\n");
        err = ENOMEM;
        goto clean_up;
    }

    if (bpf_map_get_next_key(ctx->table_fd, NULL, tuple_next_key) != 0) {
        err = ternary_table_remove_prefix(ctx, entry, key_mask);
    }

clean_up:
    if (tuple_next_key != NULL)
        free(tuple_next_key);

    close_object_fd(&(ctx->table_fd));
    return err;
}

int psabpf_table_entry_del(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    char *key_buffer = NULL;
    char *key_mask_buffer = NULL;
    int return_code = NO_ERROR;

    if (ctx->is_ternary) {
        return_code = prepare_ternary_table_delete(ctx, entry, &key_mask_buffer);
        if (return_code != NO_ERROR) {
            fprintf(stderr, "failed to prepare ternary table for delete\n");
            goto clean_up;
        }
        if (entry->n_keys == 0)
            goto clean_up;
    }

    if (ctx->table_fd < 0) {
        fprintf(stderr, "can't delete entry: table not opened\n");
        return EBADF;
    }
    if (ctx->key_size == 0) {
        fprintf(stderr, "zero-size key is not supported\n");
        return ENOTSUP;
    }

    /* remove all entries from table if key is not present */
    if (entry->n_keys == 0) {
        if (ctx->table_type == BPF_MAP_TYPE_ARRAY)
            fprintf(stderr, "removing entries from array map may take a while\n");
        return delete_all_table_entries(ctx->table_fd, ctx->key_size);
    }

    /* prepare buffers for map key */
    key_buffer = malloc(ctx->key_size);
    if (key_buffer == NULL) {
        fprintf(stderr, "not enough memory\n");
        return_code = ENOMEM;
        goto clean_up;
    }

    return_code = construct_buffer(key_buffer, ctx->key_size, ctx, entry,
                                   fill_key_btf_info, fill_key_byte_by_byte);
    if (return_code != NO_ERROR) {
        fprintf(stderr, "failed to construct key\n");
        goto clean_up;
    }

    if (ctx->is_ternary == true && key_mask_buffer != NULL)
        mem_bitwise_and((uint32_t *) key_buffer, (uint32_t *) key_mask_buffer, ctx->key_size);

    /* delete pointed entry */
    return_code = bpf_map_delete_elem(ctx->table_fd, key_buffer);
    if (return_code != NO_ERROR) {
        return_code = errno;
        fprintf(stderr, "failed to delete entry: %s\n", strerror(errno));
    }

clean_up:
    /* cleanup ternary table */
    if (ctx->is_ternary)
        post_ternary_table_delete(ctx, entry, key_mask_buffer);

    if (key_buffer != NULL)
        free(key_buffer);
    if (key_mask_buffer != NULL)
        free(key_mask_buffer);

    return return_code;
}
