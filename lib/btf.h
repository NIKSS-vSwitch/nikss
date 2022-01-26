#ifndef __PSABPF_BTF_H
#define __PSABPF_BTF_H

#include <stdint.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <linux/btf.h>

const struct btf_type * psabtf_get_type_by_id(struct btf * btf, uint32_t type_id);

uint32_t psabtf_get_type_id_by_name(struct btf * btf, const char * name);

typedef struct psabtf_struct_member_md {
    const struct btf_member * member;
    int index;
    uint32_t effective_type_id;
    size_t bit_offset;
} psabtf_struct_member_md_t;

int psabtf_get_member_md_by_name(struct btf * btf, uint32_t type_id,
        const char * member_name, psabtf_struct_member_md_t * md);
int psabtf_get_member_md_by_index(struct btf * btf, uint32_t type_id, uint16_t index,
        psabtf_struct_member_md_t * md);
uint32_t psabtf_get_member_type_id_by_name(struct btf * btf, uint32_t type_id,
        const char * member_name);

size_t psabtf_get_type_size_by_id(struct btf * btf, uint32_t type_id);

int load_btf(psabpf_context_t *psabpf_ctx, psabpf_btf_t *btf);
void free_btf(psabpf_btf_t *btf);

int open_bpf_map(psabpf_context_t *psabpf_ctx, const char *name, psabpf_btf_t *btf, psabpf_bpf_map_descriptor_t *md);

#endif  // __PSABPF_BTF_H
