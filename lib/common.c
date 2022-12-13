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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bpf_defs.h"
#include "btf.h"
#include "common.h"

int str_ends_with(const char *str, const char *suffix)
{
    size_t len_str = strlen(str);
    size_t len_suffix = strlen(suffix);
    if (len_suffix > len_str) {
        return 0;
    }
    return strncmp(str + len_str - len_suffix, suffix, len_suffix) == 0;
}

bool remove_suffix_from_str(char *str, const char *suffix)
{
    if (!str_ends_with(str, suffix)) {
        return false;
    }

    unsigned len = strlen(str);
    unsigned suffix_len = strlen(suffix);

    str[len - suffix_len] = '\0';
    return true;
}

void mem_bitwise_and(uint32_t *dst, uint32_t *mask, size_t len)
{
    for (size_t i = 0; i < len / 4; i++) {
        *dst = (uint32_t) ((*dst) & (*mask));
        ++dst; ++mask;
    }
}

void swap_byte_order(char *data, size_t len)
{
    for (size_t i = 0; i < len / 2; ++i) {
        char *byte1 = data + i;
        char *byte2 = data + len - 1 - i;
        char tmp = *byte1;
        *byte1 = *byte2;
        *byte2 = tmp;
    }
}

void close_object_fd(int *fd)
{
    if (*fd >= 0) {
        close(*fd);
    }
    *fd = -1;
}

int build_ebpf_map_filename(char *buffer, size_t maxlen, nikss_context_t *ctx, const char *name)
{
    return snprintf(buffer, maxlen, "%s/%s%u/maps/%s",
                    BPF_FS, PIPELINE_PREFIX, ctx->pipeline_id, name);
}

int build_ebpf_prog_filename(char *buffer, size_t maxlen, nikss_context_t *ctx, const char *name)
{
    return snprintf(buffer, maxlen, "%s/%s%u/%s",
                    BPF_FS, PIPELINE_PREFIX, ctx->pipeline_id, name);
}

int build_ebpf_pipeline_path(char *buffer, size_t maxlen, nikss_context_t *ctx)
{
    return snprintf(buffer, maxlen, "%s/%s%u",
                    BPF_FS, PIPELINE_PREFIX, ctx->pipeline_id);
}

void free_struct_field_descriptor_set(nikss_struct_field_descriptor_set_t *fds)
{
    if (fds == NULL) {
        return;
    }

    if (fds->fields != NULL) {
        for (unsigned i = 0; i < fds->n_fields; i++) {
            if (fds->fields[i].name != NULL) {
                free((void *) fds->fields[i].name);
            }
        }

        free(fds->fields);
        fds->fields = NULL;
    }
    fds->n_fields = 0;
}

static int setup_struct_field_descriptor_set_no_btf(nikss_struct_field_descriptor_set_t *fds, size_t data_size)
{
    fds->fields = calloc(1, sizeof(nikss_struct_field_descriptor_t));
    if (fds->fields == NULL) {
        fprintf(stderr, "not enough memory\n");
        return ENOMEM;
    }

    /* must be malloc'ed because later we assume all fields are dynamically allocated */
    fds->fields[0].name = strdup("data");
    if (fds->fields[0].name == NULL) {
        fprintf(stderr, "not enough memory\n");
        return ENOMEM;
    }

    fds->fields[0].data_len = data_size;
    fds->fields[0].data_offset = 0;
    fds->fields[0].type = NIKSS_STRUCT_FIELD_TYPE_DATA;
    fds->n_fields = 1;

    return NO_ERROR;
}

/* no memory allocation */
/* NOLINTNEXTLINE(misc-no-recursion): this is the simplest way to count all the fields in any data structure */
static size_t count_total_fields(nikss_btf_t *btf_md, uint32_t type_id)
{
    const struct btf_type *type = btf_get_type_by_id(btf_md->btf, type_id);

    if (btf_is_int(type) || btf_is_array(type)) {
        return 1;
    }

    if (!btf_is_struct(type)) {
        return 1;
    }

    unsigned struct_entries = btf_vlen(type);
    unsigned total_entries = struct_entries;

    for (unsigned i = 0; i < struct_entries; i++) {
        btf_struct_member_md_t md;
        if (btf_get_member_md_by_index(btf_md->btf, type_id, i, &md) != NO_ERROR) {
            fprintf(stderr, "invalid field or type\n");
            return 0;
        }

        /* Let's skip a bpf_spin_lock field.
         * This is an internal field not relevant to a user. */
        const struct btf_type *member_type = btf_get_type_by_id(btf_md->btf, md.effective_type_id);
        if (member_type == NULL) {
            fprintf(stderr, "invalid type\n");
            return false;
        }
        const char *type_name = btf__name_by_offset(btf_md->btf, member_type->name_off);
        if (type_name == NULL) {
            fprintf(stderr, "invalid type\n");
            return false;
        }
        if (strcmp(type_name, "bpf_spin_lock") == 0) {
            total_entries = total_entries - 1;
            continue;
        }


        if (btf_is_struct(member_type)) {
            /* We need two additional entries per struct - for struct start and struct end,
             * but first one is already included as member of parent structure */
            total_entries = total_entries + count_total_fields(btf_md, md.effective_type_id) + 1;
        }
    }

    return total_entries;
}

/* NOLINTNEXTLINE(misc-no-recursion): this is the simplest way to build nested metadata tree for any data structure */
static int setup_struct_field_descriptor_set_btf(nikss_btf_t *btf_md, nikss_struct_field_descriptor_set_t *fds,
                                                 uint32_t type_id, unsigned *field_idx, const size_t base_offset)
{
    const struct btf_type *type = btf_get_type_by_id(btf_md->btf, type_id);
    if (type == NULL) {
        fprintf(stderr, "invalid type id: %u\n", type_id);
        return EINVAL;
    }

    if (btf_is_int(type) || btf_is_array(type)) {
        if (*field_idx >= fds->n_fields) {
            goto too_many_fields;
        }

        fds->fields[*field_idx].type = NIKSS_STRUCT_FIELD_TYPE_DATA;
        fds->fields[*field_idx].data_offset = base_offset;
        fds->fields[*field_idx].data_len = btf_get_type_size_by_id(btf_md->btf, type_id);

        /* hide type name (e.g. 'unsigned int'), but we don't have information about name used in C code */
        char name_tmp[128];
        snprintf(&name_tmp[0], sizeof(name_tmp), "field%u", *field_idx);
        fds->fields[*field_idx].name = strdup(name_tmp);
        if (fds->fields[*field_idx].name == NULL) {
            fprintf(stderr, "not enough memory\n");
            return ENOMEM;
        }

        (*field_idx)++;
        return NO_ERROR;
    }

    if (!btf_is_struct(type)) {
        fprintf(stderr, "invalid type: expected struct\n");
        return EINVAL;
    }

    unsigned entries = btf_vlen(type);
    for (unsigned i = 0; i < entries; i++) {
        btf_struct_member_md_t md;
        if (btf_get_member_md_by_index(btf_md->btf, type_id, i, &md) != NO_ERROR) {
            fprintf(stderr, "invalid field or type\n");
            return 0;
        }

        /* Let's skip a bpf_spin_lock field.
         * This is an internal field not relevant to a user. */
        const struct btf_type *member_type = btf_get_type_by_id(btf_md->btf, md.effective_type_id);
        if (member_type == NULL) {
            fprintf(stderr, "invalid type\n");
            return EINVAL;
        }
        const char *type_name = btf__name_by_offset(btf_md->btf, member_type->name_off);
        if (type_name == NULL) {
            fprintf(stderr, "invalid type\n");
            return EINVAL;
        }
        if (strcmp(type_name, "bpf_spin_lock") == 0) {
            continue;
        }

        if (*field_idx >= fds->n_fields) {
            goto too_many_fields;
        }

        fds->fields[*field_idx].type = NIKSS_STRUCT_FIELD_TYPE_DATA;
        fds->fields[*field_idx].data_offset = base_offset + md.bit_offset / 8;
        fds->fields[*field_idx].data_len = btf_get_type_size_by_id(btf_md->btf, md.effective_type_id);
        const char *field_name = btf__name_by_offset(btf_md->btf, md.member->name_off);
        if (field_name != NULL) {
            fds->fields[*field_idx].name = strdup(field_name);
            if (fds->fields[*field_idx].name == NULL) {
                fprintf(stderr, "not enough memory\n");
                return ENOMEM;
            }
        }

        if (btf_is_struct(member_type)) {
            fds->fields[*field_idx].type = NIKSS_STRUCT_FIELD_TYPE_STRUCT_START;
            (*field_idx)++;
            if (*field_idx >= fds->n_fields) {
                goto too_many_fields;
            }
            int ret = setup_struct_field_descriptor_set_btf(btf_md, fds, md.effective_type_id, field_idx, base_offset + md.bit_offset / 8);
            if (ret != NO_ERROR) {
                return ret;
            }

            if (*field_idx >= fds->n_fields) {
                goto too_many_fields;
            }
            /* field_idx should point outside the last inserted entry, now add marker
             * for struct end. For now offset, len and name are not set */
            fds->fields[*field_idx].type = NIKSS_STRUCT_FIELD_TYPE_STRUCT_END;
        }

        (*field_idx)++;
    }

    return NO_ERROR;

too_many_fields:
    fprintf(stderr, "to many fields\n");
    return EFBIG;
}

int parse_struct_type(nikss_btf_t *btf_md, uint32_t type_id, size_t data_size, nikss_struct_field_descriptor_set_t *fds)
{
    if (type_id == 0) {
        fprintf(stderr, "warning: BTF type not found, placing all the data in a single field\n");
        fds->decoded_with_btf = false;
        return setup_struct_field_descriptor_set_no_btf(fds, data_size);
    }

    fds->n_fields = count_total_fields(btf_md, type_id);
    if (fds->n_fields != 0) {
        fds->fields = calloc(fds->n_fields, sizeof(nikss_struct_field_descriptor_t));
    }
    if (fds->n_fields == 0 || fds->fields == NULL) {
        fprintf(stderr, "failed to count fields\n");
        return EINVAL;
    }

    fds->decoded_with_btf = true;
    unsigned field_idx = 0;
    return setup_struct_field_descriptor_set_btf(btf_md, fds, type_id, &field_idx, 0);
}

nikss_struct_field_descriptor_t *get_struct_field_descriptor(nikss_struct_field_descriptor_set_t *fds, size_t index)
{
    if (fds == NULL) {
        return NULL;
    }

    if (index >= fds->n_fields) {
        return NULL;
    }
    if (fds->fields[index].type == NIKSS_STRUCT_FIELD_TYPE_UNKNOWN) {
        return NULL;
    }

    return &fds->fields[index];
}

void free_struct_field_set(nikss_struct_field_set_t *sfs)
{
    if (sfs == NULL) {
        return;
    }

    if (sfs->fields != NULL) {
        for (unsigned i = 0; i < sfs->n_fields; i++) {
            if (sfs->fields[i].data != NULL) {
                free(sfs->fields[i].data);
            }
            if (sfs->fields[i].name != NULL) {
                free((void *) sfs->fields[i].name);
            }
        }
        free(sfs->fields);
    }

    sfs->fields = NULL;
    sfs->n_fields = 0;
}

int struct_field_set_append(nikss_struct_field_set_t *sfs, const void *data, size_t data_len)
{
    if (sfs == NULL) {
        return EINVAL;
    }
    if (data == NULL || data_len < 1) {
        return ENODATA;
    }

    size_t new_size = (sfs->n_fields + 1) * sizeof(nikss_struct_field_t);
    nikss_struct_field_t *tmp_array = malloc(new_size);

    if (tmp_array == NULL) {
        return ENOMEM;
    }

    if (sfs->n_fields != 0) {
        memcpy(tmp_array, sfs->fields, (sfs->n_fields) * sizeof(nikss_struct_field_t));
    }
    if (sfs->fields != NULL) {
        free(sfs->fields);
    }
    sfs->fields = tmp_array;

    sfs->fields[sfs->n_fields].data = malloc(data_len);
    if (sfs->fields[sfs->n_fields].data == NULL) {
        return ENOMEM;
    }

    sfs->fields[sfs->n_fields].type = NIKSS_STRUCT_FIELD_TYPE_DATA;
    memcpy(sfs->fields[sfs->n_fields].data, data, data_len);
    sfs->fields[sfs->n_fields].data_len = data_len;
    sfs->fields[sfs->n_fields].name = NULL;

    sfs->n_fields += 1;

    return NO_ERROR;
}

int construct_struct_from_fields(nikss_struct_field_set_t *data, nikss_struct_field_descriptor_set_t *fds,
                                 char *buffer, size_t buffer_len)
{
    memset(buffer, 0, buffer_len);

    /* If passed number of fields is equal to number of fields of structure then try build field by field */
    unsigned struct_data_fields = 0;
    for (unsigned i = 0; i < fds->n_fields; i++) {
        if (fds->fields[i].type == NIKSS_STRUCT_FIELD_TYPE_DATA) {
            ++struct_data_fields;
        }
    }

    if (struct_data_fields == data->n_fields) {
        unsigned field_idx = 0;
        bool failed = false;
        for (unsigned descriptor_idx = 0; descriptor_idx < fds->n_fields; descriptor_idx++) {
            if (fds->fields[descriptor_idx].type != NIKSS_STRUCT_FIELD_TYPE_DATA) {
                continue;
            }

            if (data->fields[field_idx].data_len > fds->fields[descriptor_idx].data_len) {
                failed = true;
                break;
            }

            memcpy(buffer + fds->fields[descriptor_idx].data_offset,
                   data->fields[field_idx].data,
                   data->fields[field_idx].data_len);

            ++field_idx;
        }
        if (!failed) {
            fix_struct_data_byte_order(fds, buffer, buffer_len);
            return NO_ERROR;
        }
    }

    fprintf(stderr, "failed to construct data type based on fields, trying byte by byte...\n");

    /* We can build structure if total length of data is equal to length of struct type */
    size_t total_size = 0;
    for (unsigned i = 0; i < data->n_fields; i++) {
        total_size += data->fields[i].data_len;
    }

    if (total_size == buffer_len) {
        size_t offset = 0;
        for (unsigned i = 0; i < data->n_fields; i++) {
            memcpy(buffer + offset, data->fields[i].data, data->fields[i].data_len);
            offset += data->fields[i].data_len;
        }
        return NO_ERROR;
    }

    fprintf(stderr, "failed to construct data type\n");
    return EINVAL;
}

void fix_struct_data_byte_order(nikss_struct_field_descriptor_set_t *fds, char *buffer, size_t buffer_len) {
    if (!fds->decoded_with_btf) {
        return;
    }

    for (unsigned descriptor_idx = 0; descriptor_idx < fds->n_fields; descriptor_idx++) {
        if (fds->fields[descriptor_idx].type != NIKSS_STRUCT_FIELD_TYPE_DATA) {
            continue;
        }
        if (fds->fields[descriptor_idx].data_len + fds->fields[descriptor_idx].data_offset > buffer_len) {
            /* silently ignore error, probably should be caught somewhere else */
            break;
        }
        if (fds->fields[descriptor_idx].data_len > 8) {
            swap_byte_order(buffer + fds->fields[descriptor_idx].data_offset,
                            fds->fields[descriptor_idx].data_len);
        }
    }
}
