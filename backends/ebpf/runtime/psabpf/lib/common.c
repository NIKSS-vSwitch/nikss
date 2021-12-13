#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "common.h"

int str_ends_with(const char *str, const char *suffix)
{
    size_t len_str = strlen(str);
    size_t len_suffix = strlen(suffix);
    if (len_suffix > len_str)
        return 0;
    return strncmp(str + len_str - len_suffix, suffix, len_suffix) == 0;
}

void mem_bitwise_and(uint32_t *dst, uint32_t *mask, size_t len)
{
    for (int i = 0; i < len / 4; i++) {
        *dst = (uint32_t) ((*dst) & (*mask));
        ++dst; ++mask;
    }
}

void close_object_fd(int *fd)
{
    if (*fd >= 0)
        close(*fd);
    *fd = -1;
}

int build_ebpf_map_path(char *buffer, size_t maxlen, psabpf_context_t *psabpf_ctx)
{
    return snprintf(buffer, maxlen, "%s/%s%u/maps",
                    BPF_FS, PIPELINE_PREFIX, psabpf_context_get_pipeline(psabpf_ctx));
}
