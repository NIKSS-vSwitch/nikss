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

#ifndef __NIKSS_PIPELINE_H
#define __NIKSS_PIPELINE_H

#include <nikss.h>

#ifdef __cplusplus
extern "C" {
#endif

bool nikss_pipeline_exists(nikss_context_t *ctx);
/* This function should load BPF program and initialize default maps (call map initializer program) */
int nikss_pipeline_load(nikss_context_t *ctx, const char *file);
int nikss_pipeline_unload(nikss_context_t *ctx);
int nikss_pipeline_add_port(nikss_context_t *ctx, const char *interface, int *port_id);
int nikss_pipeline_del_port(nikss_context_t *ctx, const char *interface);

typedef struct nikss_port_spec {
    const char *name;
    unsigned id;
} nikss_port_spec_t;

typedef struct nikss_port_list {
    void *iface_list;
    void *current_iface;
    nikss_port_spec_t current_port;
    unsigned xdp_prog_id; /* XDP program is always present if port is attached */
} nikss_port_list_t;

int nikss_port_list_init(nikss_port_list_t *list, nikss_context_t *ctx);
void nikss_port_list_free(nikss_port_list_t *list);

nikss_port_spec_t * nikss_port_list_get_next_port(nikss_port_list_t *list);
const char * nikss_port_spec_get_name(nikss_port_spec_t *port);
unsigned nikss_port_sepc_get_id(nikss_port_spec_t *port);
void nikss_port_spec_free(nikss_port_spec_t *port);

/* seconds since UNIX timestamp, 0 on error */
uint64_t nikss_pipeline_get_load_timestamp(nikss_context_t *ctx);

bool nikss_pipeline_is_TC_based(nikss_context_t *ctx);
bool nikss_pipeline_has_egress_program(nikss_context_t *ctx);

typedef struct nikss_pipeline_object {
    char name[256];
} nikss_pipeline_object_t;

typedef struct nikss_pipeline_objects_list {
    void *directory;
    nikss_pipeline_object_t current_object;
    char base_objects_path[256];
} nikss_pipeline_objects_list_t;

int nikss_pipeline_objects_list_init(nikss_pipeline_objects_list_t *list, nikss_context_t *ctx);
void nikss_pipeline_objects_list_free(nikss_pipeline_objects_list_t *list);

nikss_pipeline_object_t * nikss_pipeline_objects_list_get_next_object(nikss_pipeline_objects_list_t *list);
const char * nikss_pipeline_object_get_name(nikss_pipeline_object_t *obj);
void nikss_pipeline_object_free(nikss_pipeline_object_t *obj);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif  /* __NIKSS_PIPELINE_H */
