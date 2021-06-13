#include "psabpf.h"

////// ForwardingConfig
typedef struct psabpf_pipeline {
    psabpf_pipeline_id_t id;
    const char *obj;
} psabpf_pipeline_t;

void psabpf_pipeline_init(psabpf_pipeline_t *pipeline);
void psabpf_pipeline_free(psabpf_pipeline_t *pipeline);

void psabpf_pipeline_setid(psabpf_pipeline_t *pipeline, int pipeline_id);
void psabpf_pipeline_setobj(psabpf_pipeline_t *pipeline, char *obj);

/* This function should load BPF program and initialize default maps (call map initializer program) */
bool psabpf_pipeline_exists(psabpf_pipeline_t *pipeline);
int psabpf_pipeline_load(psabpf_pipeline_t *pipeline);
int psabpf_pipeline_unload(psabpf_pipeline_t *pipeline);
int psabpf_pipeline_add_port(psabpf_pipeline_t *pipeline, char *intf);
int psabpf_pipeline_del_port(psabpf_pipeline_t *pipeline, char *intf);
