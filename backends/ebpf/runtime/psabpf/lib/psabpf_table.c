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

int str_ends_with(const char *str, const char *suffix)
{
    size_t len_str = strlen(str);
    size_t len_suffix = strlen(suffix);
    if (len_suffix >  len_str)
        return 0;
    return strncmp(str + len_str - len_suffix, suffix, len_suffix) == 0;
}

void psabpf_table_entry_ctx_init(psabpf_table_entry_ctx_t *ctx)
{
    if (ctx == NULL)
        return;
    memset(ctx, 0, sizeof(psabpf_table_entry_ctx_t));

    /* 0 is a valid file descriptor */
    ctx->table_fd = -1;
    ctx->associated_prog = -1;
}

void psabpf_table_entry_ctx_free(psabpf_table_entry_ctx_t *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->btf)
        btf__free(ctx->btf);
    ctx->btf = NULL;

    if (ctx->table_fd >= 0)
        close(ctx->table_fd);
    ctx->table_fd = -1;

    if (ctx->associated_prog >= 0)
        close(ctx->associated_prog);
    ctx->associated_prog = -1;
}

int try_load_btf_for_map_from_program(psabpf_table_entry_ctx_t *ctx,
                                      const char *program_name, const char *table_type_name)
{
    ctx->associated_prog = bpf_obj_get(program_name);
    if (ctx->associated_prog < 0)
        return -ENOENT;

    struct bpf_prog_info prog_info = {};
    unsigned len = sizeof(struct bpf_prog_info);
    int error = bpf_obj_get_info_by_fd(ctx->associated_prog, &prog_info, &len);
    if (error)
        goto free_program;

    error = btf__get_from_id(prog_info.btf_id, (struct btf **) &(ctx->btf));
    if (ctx->btf == NULL || error != 0)
        goto free_btf;

    /* Find entry in BTF for our table */
    ctx->btf_type_id = psabtf_get_type_id_by_name(ctx->btf, table_type_name);
    if (ctx->btf_type_id != 0)
        return 0;  /* found */

free_btf:
    if (ctx->btf != NULL)
        btf__free(ctx->btf);
    ctx->btf = NULL;

free_program:
    if (ctx->associated_prog >= 0)
        close(ctx->associated_prog);
    ctx->associated_prog = -1;

    return -ENOENT;
}

int psabpf_table_entry_ctx_tblname(psabpf_context_t *psabpf_ctx, psabpf_table_entry_ctx_t *ctx, const char *name)
{
    if (ctx == NULL)
        return -EPERM;

    char table_file[256];
    snprintf(table_file, sizeof(table_file), "%s/%s%u/maps/%s",
             BPF_FS, PIPELINE_PREFIX, psabpf_context_get_pipeline(psabpf_ctx), name);

    ctx->table_fd = bpf_obj_get(table_file);
    if (ctx->table_fd < 0) {
        int errno_val = errno;
        fprintf(stderr, "could not find map %s. It doesn't exists? [%s].\n",
                table_file, strerror(errno_val));
        return errno_val;
    }

    /* get key/value size */
    struct bpf_map_info info = {};
    uint32_t len = sizeof(info);
    int error;
    error = bpf_obj_get_info_by_fd(ctx->table_fd, &info, &len);
    if (error) {
        int errno_val = errno;
        fprintf(stderr, "can't get info for table: %s\n", strerror(errno_val));
        return errno_val;
    }
    ctx->table_type = info.type;
    ctx->key_size = info.key_size;
    ctx->value_size = info.value_size;

    /* get the BTF, it is optional so print only warning and return no error */
    char table_type_name[256];
    char program_file_name[256];
    const char *programs_to_search[] = { TC_INGRESS_PROG, XDP_INGRESS_PROG, TC_EGRESS_PROG };
    int number_of_programs = sizeof(programs_to_search) / sizeof(programs_to_search[0]);

    snprintf(table_type_name, sizeof(table_type_name), ".maps.%s", name);
    for (int i = 0; i < number_of_programs; i++) {
        snprintf(program_file_name, sizeof(program_file_name), "%s/%s%u/%s",
                 BPF_FS, PIPELINE_PREFIX, psabpf_context_get_pipeline(psabpf_ctx), programs_to_search[i]);

        if (try_load_btf_for_map_from_program(ctx, program_file_name, table_type_name) == 0)
            break;
    }
    if (ctx->btf_type_id == 0 || ctx->btf == NULL)
        fprintf(stderr, "couldn't find BTF info for table\n");

    return 0;
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
        return -EINVAL;
    if (mk->data == NULL)
        return -ENODATA;

    size_t new_size = (entry->n_keys + 1) * sizeof(psabpf_match_key_t *);
    psabpf_match_key_t ** tmp = malloc(new_size);
    psabpf_match_key_t * new_mk = malloc(sizeof(psabpf_match_key_t));

    if (tmp == NULL || new_mk == NULL) {
        if (tmp != NULL)
            free(tmp);
        if (new_mk != NULL)
            free(new_mk);
        return -ENOMEM;
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

    entry->n_keys += 1;

    return 0;
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
        return -EFAULT;
    if (mk->data != NULL)
        return -EEXIST;

    mk->data = malloc(size);
    if (mk->data == NULL)
        return -ENOMEM;
    memcpy(mk->data, data, size);
    mk->key_size = size;

    return 0;
}

/* only for lpm */
int psabpf_matchkey_prefix(psabpf_match_key_t *mk, uint32_t prefix)
{
    return 0;
}

/* only for ternary */
int psabpf_matchkey_mask(psabpf_match_key_t *mk, const char *mask, size_t size)
{
    return 0;
}

/* only for 'range' match */
int psabpf_matchkey_start(psabpf_match_key_t *mk, uint64_t start)
{
    return 0;
}

int psabpf_matchkey_end(psabpf_match_key_t *mk, uint64_t end)
{
    return 0;
}

int psabpf_action_param_create(psabpf_action_param_t *param, const char *data, size_t size)
{
    param->is_group_reference = false;
    param->len = size;
    if (size == 0) {
        param->data = NULL;
        return 0;
    }
    param->data = malloc(size);
    if (param->data == NULL)
        return -ENOMEM;
    memcpy(param->data, data, size);

    return 0;
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
        return -EINVAL;
    if (param->data == NULL && param->len != 0)
        return -ENODATA;

    if (param->len == 0)
        return 0;

    size_t new_size = (action->n_params + 1) * sizeof(psabpf_action_param_t);
    psabpf_action_param_t * tmp = malloc(new_size);

    if (tmp == NULL) {
        if (param->data != NULL)
            free(param->data);
        param->data = NULL;
        return -ENOMEM;
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

    return 0;
}

int write_buffer_btf(char * buffer, size_t buffer_len, size_t offset,
                     void * data, size_t data_len, psabpf_table_entry_ctx_t *ctx,
                     uint32_t dst_type_id, const char *dst_type)
{
    size_t data_type_len = psabtf_get_type_size_by_id(ctx->btf, dst_type_id);

    if (offset + data_len > buffer_len || data_len > data_type_len) {
        fprintf(stderr, "too much data in %s "
                        "(buffer len: %zu; offset: %zu; data size: %zu; type size: %zu)\n",
                dst_type, buffer_len, offset, data_len, data_type_len);
        return -EAGAIN;
    }
    memcpy(buffer + offset, data, data_len);
    return 0;
}

int fill_key_byte_by_byte(char * buffer, psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    size_t bytes_to_write = ctx->key_size;

    for (size_t i = 0; i < entry->n_keys; i++) {
        psabpf_match_key_t *mk = entry->match_keys[i];
        if (mk->key_size > bytes_to_write) {
            fprintf(stderr, "Provided keys are too long\n");
            return -1;
        }
        memcpy(buffer, mk->data, mk->key_size);
        buffer += mk->key_size;
        bytes_to_write -= mk->key_size;
    }

    /* TODO: maybe we should ignore this case */
    if (bytes_to_write > 0) {
        fprintf(stderr, "Provided keys are too short\n");
        return -1;
    }
    return 0;
}

int fill_key_btf_info(char * buffer, psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    uint32_t key_type_id = psabtf_get_member_type_id_by_name(ctx->btf, ctx->btf_type_id, "key");
    if (key_type_id == 0)
        return -EAGAIN;
    const struct btf_type *key_type = psabtf_get_type_by_id(ctx->btf, key_type_id);
    if (key_type == NULL)
        return -EAGAIN;

    if (btf_kind(key_type) == BTF_KIND_INT) {
        if (entry->n_keys != 1) {
            fprintf(stderr, "expected 1 key\n");
            return -EAGAIN;
        }
        if (entry->match_keys[0]->key_size > ctx->key_size) {
            fprintf(stderr, "too much data in key\n");
            return -1;  /* byte by byte mode will not fix this */
        }
        memcpy(buffer, entry->match_keys[0]->data, entry->match_keys[0]->key_size);
    } else if (btf_kind(key_type) == BTF_KIND_STRUCT) {
        const struct btf_member *member = btf_members(key_type);
        int entries = btf_vlen(key_type);
        if (entry->n_keys != entries) {
            fprintf(stderr, "expected %d keys, got %zu\n", entries, entry->n_keys);
            return -EAGAIN;
        }
        for (int i = 0; i < entries; i++, member++) {
            /* assume that every field is byte aligned */
            unsigned offset = btf_member_bit_offset(key_type, i) / 8;
            int ret = write_buffer_btf(buffer, ctx->key_size, offset,
                                       entry->match_keys[i]->data, entry->match_keys[i]->key_size,
                                       ctx, member->type, "key");
            if (ret != 0)
                return ret;
        }
    } else {
        fprintf(stderr, "unexpected BTF type for key\n");
        return -EAGAIN;
    }

    return 0;
}

int fill_value_byte_by_byte(char * buffer, psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
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
            return -1;
        }
    }

    for (size_t i = 0; i < entry->action->n_params; i++) {
        psabpf_action_param_t *param = &(entry->action->params[i]);
        if (param->len > bytes_to_write) {
            fprintf(stderr, "Provided values are too long\n");
            return -1;
        }
        memcpy(buffer, param->data, param->len);
        buffer += param->len;
        bytes_to_write -= param->len;
    }

    /* TODO: maybe we should ignore this case */
    if (bytes_to_write > 0) {
        fprintf(stderr, "Provided values are too short\n");
        return -1;
    }
    return 0;
}

int fill_action_id(char * buffer, psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry,
                   uint32_t value_type_id, const struct btf_type *value_type)
{
    psabtf_struct_member_md_t action_md = {};
    if (psabtf_get_member_md_by_name(ctx->btf, value_type_id, "action", &action_md) != 0) {
        fprintf(stderr, "action id entry not found\n");
        return -ENOENT;
    }
    return write_buffer_btf(buffer, ctx->value_size,
                            btf_member_bit_offset(value_type, action_md.index) / 8,
                            &(entry->action->action_id), sizeof(entry->action->action_id),
                            ctx, action_md.effective_type_id, "action id");
}

int fill_action_data(char * buffer, psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry,
                     uint32_t value_type_id, const struct btf_type *value_type)
{
    size_t base_offset, offset;
    int ret;

    /* find union with action data */
    psabtf_struct_member_md_t action_union_md = {};
    if (psabtf_get_member_md_by_name(ctx->btf, value_type_id, "u", &action_union_md) != 0) {
        fprintf(stderr, "actions data structure not found\n");
        return -ENOENT;
    }
    const struct btf_type * union_type = psabtf_get_type_by_id(ctx->btf, action_union_md.effective_type_id);
    base_offset = btf_member_bit_offset(value_type, action_union_md.index) / 8;

    /* find action data structure in the union */
    psabtf_struct_member_md_t action_data_md = {};
    if (psabtf_get_member_md_by_index(ctx->btf, action_union_md.effective_type_id,
                                      entry->action->action_id, &action_data_md) != 0) {
        fprintf(stderr, "action with id %u does not exist\n", entry->action->action_id);
        return -EPERM;  /* not fixable, invalid action ID */
    }
    /* to be sure of offset, take into account offset of action data structure in the union */
    base_offset = base_offset + (btf_member_bit_offset(union_type, action_data_md.index) / 8);
    const struct btf_type * data_type = psabtf_get_type_by_id(ctx->btf, action_data_md.effective_type_id);

    /* fill action data */
    int entries = btf_vlen(data_type);
    if (entry->action->n_params != entries) {
        fprintf(stderr, "expected %d action parameters, got %zu\n",
                entries, entry->action->n_params);
        return -EAGAIN;
    }
    const struct btf_member *member = btf_members(data_type);
    for (int i = 0; i < entries; i++, member++) {
        offset = btf_member_bit_offset(data_type, i) / 8;
        ret = write_buffer_btf(buffer, ctx->value_size, base_offset + offset,
                               entry->action->params[i].data, entry->action->params[i].len,
                               ctx, member->type, "value");
        if (ret != 0)
            return ret;
    }

    return 0;
}

int fill_action_references(char * buffer, psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry,
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
            return -EAGAIN;
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
                                   ctx, member->type, "reference type");
            if (ret != 0)
                return ret;
            continue;
        }
        if (entry_ref_used) {
            entry_ref_used = false;
            current_data++; used_params++;
            if (used_params >= entry->action->n_params) {
                fprintf(stderr, "not enough member/group references\n");
                return -EAGAIN;
            }
        }
        /* now we can write reference, hurrah!!! */
        offset = btf_member_bit_offset(value_type, i) / 8;
        ret = write_buffer_btf(buffer, ctx->value_size, offset, current_data->data,
                               current_data->len, ctx, member->type, "reference");
        if (ret != 0)
            return ret;
        entry_ref_used = true;
    }
    if (entry_ref_used)
        used_params++;
    if (used_params != entry->action->n_params) {
        fprintf(stderr, "too many member/group references\n");
        return -EAGAIN;
    }

    return 0;
}

int fill_value_btf_info(char * buffer, psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    size_t offset, base_offset;
    int ret;

    uint32_t value_type_id = psabtf_get_member_type_id_by_name(ctx->btf, ctx->btf_type_id, "value");
    if (value_type_id == 0)
        return -EAGAIN;
    const struct btf_type *value_type = psabtf_get_type_by_id(ctx->btf, value_type_id);
    if (value_type == NULL)
        return -EAGAIN;

    if (btf_kind(value_type) != BTF_KIND_STRUCT) {
        fprintf(stderr, "expected struct as a map value\n");
        return -EAGAIN;
    }

    if (ctx->is_indirect == false) {
        ret = fill_action_id(buffer, ctx, entry, value_type_id, value_type);
        if (ret != 0)
            return ret;

        ret = fill_action_data(buffer, ctx, entry, value_type_id, value_type);
        if (ret != 0)
            return ret;
    } else {
        ret = fill_action_references(buffer, ctx, entry, value_type_id, value_type);
        if (ret != 0)
            return ret;
    }

    return 0;
}

/* Please use this function instead of using directly family of fill_*() functions */
int construct_buffer(char * buffer, size_t buffer_len,
                     psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry,
                     int (*btf_info_func)(char *, psabpf_table_entry_ctx_t *, psabpf_table_entry_t *),
                     int (*byte_by_byte_func)(char *, psabpf_table_entry_ctx_t *, psabpf_table_entry_t *))
{
    /* When BTF info mode fails we can fallback to byte by byte mode */
    int return_code = -EAGAIN;
    if (ctx->btf != NULL && ctx->btf_type_id != 0) {
        memset(buffer, 0, buffer_len);
        return_code = btf_info_func(buffer, ctx, entry);
    }
    if (return_code == -EAGAIN) {
        memset(buffer, 0, buffer_len);
        return_code = byte_by_byte_func(buffer, ctx, entry);
    }
    return return_code;
}

int psabpf_table_entry_add(psabpf_table_entry_ctx_t *ctx, psabpf_table_entry_t *entry)
{
    char *key_buffer = NULL;
    char *value_buffer = NULL;
    int return_code = 0;

    if (ctx->table_fd < 0) {
        fprintf(stderr, "can't add entry: table not opened\n");
        return -EBADF;
    }
    if (ctx->key_size == 0 || ctx->value_size == 0) {
        fprintf(stderr, "zero-size key or value is not supported\n");
        return -ENOTSUP;
    }
    if (entry->action == NULL) {
        fprintf(stderr, "missing action specification\n");
        return -ENODATA;
    }

    /* prepare buffers for map key/value */
    key_buffer = malloc(ctx->key_size);
    value_buffer = malloc(ctx->value_size);
    if (key_buffer == NULL || value_buffer == NULL) {
        fprintf(stderr, "not enough memory\n");
        return_code = -ENOMEM;
        goto clean_up;
    }

    return_code = construct_buffer(key_buffer, ctx->key_size, ctx, entry,
                                   fill_key_btf_info, fill_key_byte_by_byte);
    if (return_code != 0) {
        fprintf(stderr, "failed to construct key\n");
        goto clean_up;
    }

    return_code = construct_buffer(value_buffer, ctx->value_size, ctx, entry,
                                   fill_value_btf_info, fill_value_byte_by_byte);
    if (return_code != 0) {
        fprintf(stderr, "failed to construct value\n");
        goto clean_up;
    }

    /* update map */
    uint64_t flags = BPF_NOEXIST;
    if (ctx->table_type == BPF_MAP_TYPE_ARRAY)
        flags = BPF_ANY;
    return_code = bpf_map_update_elem(ctx->table_fd, key_buffer, value_buffer, flags);
    if (return_code != 0) {
        return_code = errno;
        fprintf(stderr, "failed to add entry: %s\n", strerror(errno));
    }

clean_up:
    if (key_buffer)
        free(key_buffer);
    if (value_buffer)
        free(value_buffer);

    return return_code;
}
