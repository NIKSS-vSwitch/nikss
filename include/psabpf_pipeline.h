#include "psabpf.h"

bool psabpf_pipeline_exists(psabpf_context_t *ctx);
/* This function should load BPF program and initialize default maps (call map initializer program) */
int psabpf_pipeline_load(psabpf_context_t *ctx, const char *file);
int psabpf_pipeline_unload(psabpf_context_t *ctx);
int psabpf_pipeline_add_port(psabpf_context_t *ctx, const char *interface);
int psabpf_pipeline_del_port(psabpf_context_t *ctx, const char *interface);
