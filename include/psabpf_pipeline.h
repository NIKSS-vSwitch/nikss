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

#include "psabpf.h"

bool psabpf_pipeline_exists(psabpf_context_t *ctx);
/* This function should load BPF program and initialize default maps (call map initializer program) */
int psabpf_pipeline_load(psabpf_context_t *ctx, const char *file);
int psabpf_pipeline_unload(psabpf_context_t *ctx);
int psabpf_pipeline_add_port(psabpf_context_t *ctx, const char *interface, int *port_id);
int psabpf_pipeline_del_port(psabpf_context_t *ctx, const char *interface);

typedef struct psabpf_port_spec {
    const char *name;
    unsigned id;
} psabpf_port_spec_t;

typedef struct psabpf_port_list {
    void *iface_list;
    void *current_iface;
    psabpf_port_spec_t current_port;
    unsigned xdp_prog_id; /* XDP program is always present if port is attached */
} psabpf_port_list_t;

int psabpf_port_list_init(psabpf_port_list_t *list, psabpf_context_t *ctx);
void psabpf_port_list_free(psabpf_port_list_t *list);

psabpf_port_spec_t * psabpf_port_list_get_next_port(psabpf_port_list_t *list);
const char * psabpf_port_spec_get_name(psabpf_port_spec_t *port);
unsigned psabpf_port_sepc_get_id(psabpf_port_spec_t *port);
void psabpf_port_spec_free(psabpf_port_spec_t *port);

/* seconds since UNIX timestamp, 0 on error */
uint64_t psabpf_pipeline_get_load_timestamp(psabpf_context_t *ctx);

bool psabpf_pipeline_is_TC_based(psabpf_context_t *ctx);
bool psabpf_pipeline_has_egress_program(psabpf_context_t *ctx);

typedef struct psabpf_pipeline_object {
    char name[256];
} psabpf_pipeline_object_t;

typedef struct psabpf_pipeline_objects_list {
    void *directory;
    psabpf_pipeline_object_t current_object;
    char base_objects_path[256];
} psabpf_pipeline_objects_list_t;

int psabpf_pipeline_objects_list_init(psabpf_pipeline_objects_list_t *list, psabpf_context_t *ctx);
void psabpf_pipeline_objects_list_free(psabpf_pipeline_objects_list_t *list);

psabpf_pipeline_object_t * psabpf_pipeline_objects_list_get_next_object(psabpf_pipeline_objects_list_t *list);
const char * psabpf_pipeline_object_get_name(psabpf_pipeline_object_t *obj);
void psabpf_pipeline_object_free(psabpf_pipeline_object_t *obj);
