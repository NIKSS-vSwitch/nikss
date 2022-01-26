#ifndef P4C_PSABPF_COMMON_H
#define P4C_PSABPF_COMMON_H

#include <stdint.h>
#include "../include/psabpf.h"

int str_ends_with(const char *str, const char *suffix);

/* Data len must be aligned to 4B */
void mem_bitwise_and(uint32_t *dst, uint32_t *mask, size_t len);

void close_object_fd(int *fd);

int build_ebpf_map_filename(char *buffer, size_t maxlen, psabpf_context_t *ctx, const char *name);
int build_ebpf_prog_filename(char *buffer, size_t maxlen, psabpf_context_t *ctx, const char *name);
int build_ebpf_pipeline_path(char *buffer, size_t maxlen, psabpf_context_t *ctx);

#endif  /* P4C_PSABPF_COMMON_H */
