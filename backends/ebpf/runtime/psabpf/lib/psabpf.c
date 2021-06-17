#include <unistd.h>
#include <bpf/btf.h>

#include "../include/psabpf.h"

void psabpf_context_init(psabpf_context_t *ctx)
{
    memset( ctx, 0, sizeof(psabpf_context_t));
}

void psabpf_context_free(psabpf_context_t *ctx)
{
    if (ctx == NULL)
        return;

    memset( ctx, 0, sizeof(psabpf_context_t));
}

void psabpf_context_set_pipeline(psabpf_context_t *ctx, psabpf_pipeline_id_t pipeline_id)
{
    ctx->pipeline_id = pipeline_id;
}

psabpf_pipeline_id_t psabpf_context_get_pipeline(psabpf_context_t *ctx)
{
    return ctx->pipeline_id;
}
