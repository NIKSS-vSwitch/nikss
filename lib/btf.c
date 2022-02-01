#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <linux/bpf.h>
#include <linux/btf.h>

#include "../include/psabpf.h"
#include "btf.h"
#include "common.h"

static uint32_t follow_types(struct btf * btf, uint32_t type_id)
{
    if (type_id == 0)
        return type_id;

    const struct btf_type * type = btf__type_by_id(btf, type_id);
    while (true) {
        if (btf_is_typedef(type) || btf_is_ptr(type))
            type_id = type->type;
        else
            break;
        type = btf__type_by_id(btf, type_id);
    }

    return type_id;
}

static uint32_t find_data_section_type_id(struct btf * btf, uint32_t sec_type_id, const char *name)
{
    const struct btf_type * type = btf__type_by_id(btf, sec_type_id);
    if (type == NULL)
        return 0;

    if (!btf_is_datasec(type))
        return 0;

    unsigned entries = btf_vlen(type);
    const struct btf_var_secinfo * info = btf_var_secinfos(type);

    for (unsigned i = 0; i < entries; i++, info++) {
        const struct btf_type * entry_type = btf__type_by_id(btf, info->type);

        const char *entry_name = btf__name_by_offset(btf, entry_type->name_off);
        if (entry_name != NULL && name != NULL) {
            if (strcmp(entry_name, name) == 0) {
                return entry_type->type;
            }
        }
    }

    return 0;
}

const struct btf_type * psabtf_get_type_by_id(struct btf * btf, uint32_t type_id)
{
    type_id = follow_types(btf, type_id);
    if (type_id == 0)
        return NULL;
    return btf__type_by_id(btf, type_id);
}

static uint32_t psabtf_get_map_type_id_by_name(struct btf * btf, const char * name)
{
    uint32_t type_id = 0;
    unsigned nodes = btf__get_nr_types(btf);

    /* First find ".maps" section to avoid false positive match to name */
    for (unsigned i = 1; i <= nodes; i++) {
        const struct btf_type * type = btf__type_by_id(btf, i);
        if (!type->name_off)
            continue;
        const char * type_name = btf__name_by_offset(btf, type->name_off);
        if (type_name == NULL)
            continue;
        if (strcmp(type_name, ".maps") == 0) {
            type_id = i;
            break;
        }
    }

    if (type_id == 0) {
        fprintf(stderr, "section with maps definitions was not found, BTF is invalid or bug?");
        return 0;
    }

    /* find our map in maps section */
    type_id = find_data_section_type_id(btf, type_id, name);

    return follow_types(btf, type_id);
}

int psabtf_get_member_md_by_name(struct btf * btf, uint32_t type_id,
        const char * member_name, psabtf_struct_member_md_t * md)
{
    if (type_id == 0)
        return -EPERM;

    const struct btf_type *type = btf__type_by_id(btf, type_id);
    if (type == NULL)
        return -EPERM;
    // type must be a struct or union
    if (btf_kind(type) != BTF_KIND_STRUCT &&
        btf_kind(type) != BTF_KIND_UNION)
        return -EPERM;

    int type_entries = btf_vlen(type);
    const struct btf_member *type_member = btf_members(type);
    for (int i = 0; i < type_entries; i++, type_member++) {
        const char *name = btf__name_by_offset(btf, type_member->name_off);
        if (name == NULL)
            continue;
        if (strcmp(name, member_name) == 0) {
            md->member = type_member;
            md->index = i;
            md->effective_type_id = follow_types(btf, type_member->type);
            md->bit_offset = btf_member_bit_offset(type, i);
            return NO_ERROR;
        }
    }

    return -EPERM;
}

int psabtf_get_member_md_by_index(struct btf * btf, uint32_t type_id, uint16_t index,
                                  psabtf_struct_member_md_t * md)
{
    if (type_id == 0)
        return -EPERM;

    const struct btf_type *type = btf__type_by_id(btf, type_id);
    if (type == NULL)
        return -EPERM;
    // type must be a struct or union
    if (btf_kind(type) != BTF_KIND_STRUCT &&
        btf_kind(type) != BTF_KIND_UNION)
        return -EPERM;

    int type_entries = btf_vlen(type);
    if (index >= type_entries)
        return -EPERM;

    const struct btf_member *type_member = btf_members(type);
    type_member += index;
    md->member = type_member;
    md->index = index;
    md->effective_type_id = follow_types(btf, type_member->type);
    md->bit_offset = btf_member_bit_offset(type, index);

    return NO_ERROR;
}

uint32_t psabtf_get_member_type_id_by_name(struct btf * btf, uint32_t type_id, const char * member_name)
{
    psabtf_struct_member_md_t md = {};
    if (psabtf_get_member_md_by_name(btf, type_id, member_name, &md) != 0)
        return 0;

    return md.effective_type_id;
}

size_t psabtf_get_type_size_by_id(struct btf * btf, uint32_t type_id)
{
    const struct btf_type * type = psabtf_get_type_by_id(btf, type_id);
    if (type == NULL)
        return 0;

    switch (btf_kind(type)) {
        case BTF_KIND_INT:
        case BTF_KIND_STRUCT:
        case BTF_KIND_UNION:
            return type->size;

        case BTF_KIND_ARRAY: {
            // Should work with multidimensional arrays, but
            // LLVM collapse them into one-dimensional array.
            const struct btf_array * array_info = btf_array(type);
            // BTF is taken from kernel, so we can trust in it that there is no
            // infinite dimensional array (we do not prevent from stack overflow).
            size_t type_size = psabtf_get_type_size_by_id(btf, array_info->type);
            return type_size * (array_info->nelems);
        }

        default:
            fprintf(stderr, "unable to obtain type size\n");
    }

    return 0;
}

static int try_load_btf(psabpf_btf_t *btf, const char *program_name)
{
    btf->associated_prog = bpf_obj_get(program_name);
    if (btf->associated_prog < 0)
        return ENOENT;

    struct bpf_prog_info prog_info = {};
    unsigned len = sizeof(struct bpf_prog_info);
    int error = bpf_obj_get_info_by_fd(btf->associated_prog, &prog_info, &len);
    if (error)
        goto free_program;

    error = btf__get_from_id(prog_info.btf_id, (struct btf **) &(btf->btf));
    if (btf->btf == NULL || error != 0)
        goto free_btf;

    return NO_ERROR;

free_btf:
    if (btf->btf != NULL)
        btf__free(btf->btf);
    btf->btf = NULL;

free_program:
    if (btf->associated_prog >= 0)
        close(btf->associated_prog);
    btf->associated_prog = -1;

    return ENOENT;
}

int load_btf(psabpf_context_t *psabpf_ctx, psabpf_btf_t *btf)
{
    if (btf->btf != NULL)
        return NO_ERROR;

    char program_file_name[256];
    const char *programs_to_search[] = { TC_INGRESS_PROG, XDP_INGRESS_PROG, TC_EGRESS_PROG };
    int number_of_programs = sizeof(programs_to_search) / sizeof(programs_to_search[0]);

    for (int i = 0; i < number_of_programs; i++) {
        snprintf(program_file_name, sizeof(program_file_name), "%s/%s%u/%s",
                 BPF_FS, PIPELINE_PREFIX, psabpf_context_get_pipeline(psabpf_ctx), programs_to_search[i]);
        if (try_load_btf(btf, program_file_name) == NO_ERROR)
            break;
    }
    if (btf->btf == NULL)
        return ENOENT;

    return NO_ERROR;
}

void free_btf(psabpf_btf_t *btf)
{
    if (btf == NULL)
        return;

    if (btf->btf)
        btf__free(btf->btf);
    btf->btf = NULL;
    close_object_fd(&btf->associated_prog);
}

int open_bpf_map(psabpf_context_t *psabpf_ctx, const char *name, psabpf_btf_t *btf, psabpf_bpf_map_descriptor_t *md)
{
    char buffer[256];
    int errno_val;

    if (md == NULL)
        return EPERM;

    build_ebpf_map_filename(buffer, sizeof(buffer), psabpf_ctx, name);
    md->fd = bpf_obj_get(buffer);
    if (md->fd < 0)
        return errno;

    /* get key/value size */
    struct bpf_map_info info = {};
    uint32_t len = sizeof(info);
    errno_val = bpf_obj_get_info_by_fd(md->fd, &info, &len);
    if (errno_val) {
        errno_val = errno;
        fprintf(stderr, "can't get info for table %s: %s\n", name, strerror(errno_val));
        return errno_val;
    }

    md->type = info.type;
    md->key_size = info.key_size;
    md->value_size = info.value_size;
    md->max_entries = info.max_entries;

    /* Find entry in BTF for our map */
    if (btf != NULL && btf->btf != NULL) {
        md->btf_type_id = psabtf_get_map_type_id_by_name(btf->btf, name);
        if (md->btf_type_id == 0)
            fprintf(stderr, "can't get BTF info for %s\n", name);
    }

    return NO_ERROR;
}
