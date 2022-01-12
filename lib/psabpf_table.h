#ifndef P4C_PSABPF_TABLE_H
#define P4C_PSABPF_TABLE_H

typedef struct psabpf_bpf_map_descriptor psabpf_bpf_map_descriptor_t;
int clear_table_cache(psabpf_bpf_map_descriptor_t *map);

void move_action(psabpf_action_t *dst, psabpf_action_t *src);

#endif  /* P4C_PSABPF_TABLE_H */
