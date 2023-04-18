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

#include <nikss/nikss.h>

void nikss_context_init(nikss_context_t *ctx)
{
    memset( ctx, 0, sizeof(nikss_context_t));
}

void nikss_context_free(nikss_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    memset( ctx, 0, sizeof(nikss_context_t));
}

void nikss_context_set_pipeline(nikss_context_t *ctx, nikss_pipeline_id_t pipeline_id)
{
    ctx->pipeline_id = pipeline_id;
}

nikss_pipeline_id_t nikss_context_get_pipeline(nikss_context_t *ctx)
{
    return ctx->pipeline_id;
}

nikss_struct_field_type_t nikss_struct_get_field_type(nikss_struct_field_t *field)
{
    return field->type;
}

const char * nikss_struct_get_field_name(nikss_struct_field_t *field)
{
    return field->name;
}

const void * nikss_struct_get_field_data(nikss_struct_field_t *field)
{
    return field->data;
}

size_t nikss_struct_get_field_data_len(nikss_struct_field_t *field)
{
    return field->data_len;
}
