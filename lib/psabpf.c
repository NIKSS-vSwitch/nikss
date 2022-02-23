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

#include <string.h>

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

psabpf_struct_field_type_t psabpf_struct_get_field_type(psabpf_struct_field_t *field)
{
    return field->type;
}

const char * psabpf_struct_get_field_name(psabpf_struct_field_t *field)
{
    return field->name;
}

const void * psabpf_struct_get_field_data(psabpf_struct_field_t *field)
{
    return field->data;
}

size_t psabpf_struct_get_field_data_len(psabpf_struct_field_t *field)
{
    return field->data_len;
}
