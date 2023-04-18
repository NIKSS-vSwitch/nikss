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

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>

#include <nikss/nikss.h>

#include "common.h"
#include "counter.h"
#include "meter.h"
#include "table.h"

/******************************************************************************
 * Command line parsing functions
 *****************************************************************************/

static int parse_dst_table(int *argc, char ***argv, nikss_context_t *nikss_ctx,
                           nikss_table_entry_ctx_t *ctx, const char **table_name, bool can_be_last)
{
    if (table_name != NULL) {
        *table_name = **argv;
    }
    int error_code = nikss_table_entry_ctx_tblname(nikss_ctx, ctx, **argv);
    if (error_code != NO_ERROR) {
        return error_code;
    }

    if (can_be_last) {
        NEXT_ARGP();
    } else {
        NEXT_ARGP_RET();
    }

    return NO_ERROR;
}

static int parse_table_action(int *argc, char ***argv, nikss_table_entry_ctx_t *ctx,
                              nikss_action_t *action, bool can_be_last)
{
    if (is_keyword(**argv, "ref")) {
        nikss_table_entry_ctx_mark_indirect(ctx);
    } else if (is_keyword(**argv, "action")) {
        NEXT_ARGP_RET();

        if (is_keyword(**argv, "id")) {
            NEXT_ARGP_RET();
            char *ptr = NULL;
            nikss_action_set_id(action, strtoul(**argv, &ptr, 0));
            if (*ptr) {
                fprintf(stderr, "%s: unable to parse as an action id\n", **argv);
                return EINVAL;
            }
        } else if (is_keyword(**argv, "name")) {
            NEXT_ARGP_RET();
            uint32_t action_id = nikss_table_get_action_id_by_name(ctx, **argv);
            if (action_id == NIKSS_INVALID_ACTION_ID) {
                fprintf(stderr, "%s: action not found\n", **argv);
                return EINVAL;
            }
            nikss_action_set_id(action, action_id);
        } else {
            fprintf(stderr, "%s: unknown action specification", **argv);
            return EINVAL;
        }
    } else {
        fprintf(stderr, "%s: unknown keyword ", **argv);
        return EINVAL;
    }

    if (can_be_last) {
        NEXT_ARGP();
    } else {
        NEXT_ARGP_RET();
    }

    return NO_ERROR;
}

static int parse_table_key(int *argc, char ***argv, nikss_table_entry_t *entry)
{
    if (!is_keyword(**argv, "key")) {
        return NO_ERROR;
    }

    return parse_key_data(argc, argv, entry);
}

static int parse_direct_counter_entry(int *argc, char ***argv,
                                      nikss_table_entry_ctx_t *ctx, nikss_table_entry_t *entry,
                                      nikss_direct_counter_context_t *dc, nikss_counter_entry_t *counter)
{
    if (!is_keyword(**argv, "counter")) {
        return EINVAL;
    }

    NEXT_ARGP_RET();
    const char *name = **argv;

    int ret = nikss_direct_counter_ctx_name(dc, ctx, name);
    if (ret != NO_ERROR) {
        fprintf(stderr, "%s: DirectCounter not found\n", name);
        return ret;
    }

    NEXT_ARGP_RET();
    ret = parse_counter_value_str(**argv, nikss_direct_counter_get_type(dc), counter);
    if (ret != NO_ERROR) {
        return ret;
    }

    ret = nikss_table_entry_set_direct_counter(entry, dc, counter);
    if (ret != NO_ERROR) {
        fprintf(stderr, "%s: failed to append DirectCounter to table entry\n", name);
    }

    return ret;
}

static int parse_direct_meter_entry(int *argc, char ***argv,
                                    nikss_table_entry_ctx_t *ctx, nikss_table_entry_t *entry,
                                    nikss_direct_meter_context_t *dm, nikss_meter_entry_t *meter)
{
    if (!is_keyword(**argv, "meter")) {
        return EINVAL;
    }

    NEXT_ARGP_RET();
    const char *meter_name = **argv;

    int ret = nikss_direct_meter_ctx_name(dm, ctx, meter_name);
    if (ret != NO_ERROR) {
        fprintf(stderr, "%s: DirectMeter not found\n", meter_name);
        return ret;
    }

    ret = parse_meter_data(argc, argv, meter);
    if (ret != NO_ERROR) {
        return ret;
    }

    ret = nikss_table_entry_set_direct_meter(entry, dm, meter);
    if (ret != NO_ERROR) {
        fprintf(stderr, "%s: failed to append DirectMeter to table entry\n", meter_name);
    }

    return ret;
}

static int parse_action_data(int *argc, char ***argv, nikss_table_entry_ctx_t *ctx,
                             nikss_table_entry_t *entry, nikss_action_t *action)
{
    bool indirect_table = nikss_table_entry_ctx_is_indirect(ctx);

    if (!is_keyword(**argv, "data")) {
        if (indirect_table) {
            fprintf(stderr, "expected action reference\n");
            return EINVAL;
        }
        return NO_ERROR;
    }

    do {
        NEXT_ARGP_RET();
        if (is_keyword(**argv, "priority")) {
            return NO_ERROR;
        }

        bool ref_is_group_ref = false;
        if (indirect_table) {
            if (is_keyword(**argv, "group")) {
                ref_is_group_ref = true;
                NEXT_ARGP_RET();
            }
        } else {
            if (is_keyword(**argv, "counter")) {
                nikss_direct_counter_context_t dc;
                nikss_counter_entry_t counter;

                nikss_direct_counter_ctx_init(&dc);
                nikss_counter_entry_init(&counter);

                int ret = parse_direct_counter_entry(argc, argv, ctx, entry, &dc, &counter);
                nikss_counter_entry_free(&counter);
                nikss_direct_counter_ctx_free(&dc);
                if (ret != NO_ERROR) {
                    return ret;
                }

                continue;
            }

            if (is_keyword(**argv, "meter")) {
                nikss_direct_meter_context_t dm;
                nikss_meter_entry_t meter;

                nikss_direct_meter_ctx_init(&dm);
                nikss_meter_entry_init(&meter);

                int ret = parse_direct_meter_entry(argc, argv, ctx, entry, &dm, &meter);
                nikss_meter_entry_free(&meter);
                nikss_direct_meter_ctx_free(&dm);
                if (ret != NO_ERROR) {
                    return ret;
                }

                continue;
            }
        }

        nikss_action_param_t param;
        int error_code = translate_data_to_bytes(**argv, &param, CTX_ACTION_DATA);
        if (error_code != NO_ERROR) {
            nikss_action_param_free(&param);
            return error_code;
        }
        if (ref_is_group_ref) {
            nikss_action_param_mark_group_reference(&param);
        }
        error_code = nikss_action_param(action, &param);
        if (error_code != NO_ERROR) {
            return error_code;
        }
    } while ((*argc) > 1);
    NEXT_ARGP();

    return NO_ERROR;
}

static int parse_entry_priority(int *argc, char ***argv, nikss_table_entry_t *entry)
{
    if (!is_keyword(**argv, "priority")) {
        return NO_ERROR;
    }
    NEXT_ARGP_RET();

    char *ptr = NULL;
    nikss_table_entry_priority(entry, strtoul(**argv, &ptr, 0));
    if (*ptr) {
        fprintf(stderr, "%s: unable to parse priority\n", **argv);
        return EINVAL;
    }
    NEXT_ARGP();

    return NO_ERROR;
}

static int parse_table_type(int *argc, char ***argv, nikss_table_entry_ctx_t *ctx)
{
    if (is_keyword(**argv, "ref")) {
        nikss_table_entry_ctx_mark_indirect(ctx);
        NEXT_ARGP();
    }
    return NO_ERROR;
}

/******************************************************************************
 * JSON functions
 *****************************************************************************/

static json_t *create_json_entry_action_params(nikss_table_entry_ctx_t *ctx, nikss_table_entry_t *entry)
{
    json_t *param_root = json_array();
    if (param_root == NULL) {
        return NULL;
    }

    nikss_action_param_t *ap = NULL;
    while ((ap = nikss_action_param_get_next(entry)) != NULL) {
        json_t *param_entry = json_object();
        if (param_entry == NULL) {
            json_decref(param_root);
            return NULL;
        }
        char *data = convert_bin_data_to_hexstr(nikss_action_param_get_data(ap),
                                                nikss_action_param_get_data_len(ap));
        if (data == NULL) {
            json_decref(param_root);
            json_decref(param_entry);
            return NULL;
        }
        const char *name = nikss_action_param_get_name(ctx, entry, ap);

        if (name != NULL) {
            json_object_set_new(param_entry, "name", json_string(name));
        }
        json_object_set_new(param_entry, "value", json_string(data));
        json_array_append(param_root, param_entry);

        free(data);
        nikss_action_param_free(ap);
    }

    return param_root;
}

static json_t *create_json_entry_action(nikss_table_entry_ctx_t *ctx, nikss_table_entry_t *entry)
{
    json_t *action_root = json_object();
    if (action_root == NULL) {
        return NULL;
    }

    uint32_t action_id = nikss_action_get_id(entry);
    json_object_set_new(action_root, "id", json_integer(action_id));
    const char *action_name = nikss_action_get_name(ctx, action_id);
    if (action_name != NULL) {
        json_object_set_new(action_root, "name", json_string(action_name));
    }

    json_t *action_params = create_json_entry_action_params(ctx, entry);
    if (action_params == NULL) {
        json_decref(action_root);
        return NULL;
    }
    json_object_set_new(action_root, "parameters", action_params);

    return action_root;
}

static json_t *create_json_entry_references(nikss_table_entry_ctx_t *ctx, nikss_table_entry_t *entry)
{
    json_t *refs_root = json_array();
    if (refs_root == NULL) {
        return NULL;
    }

    nikss_action_param_t *ap = NULL;
    while ((ap = nikss_action_param_get_next(entry)) != NULL) {
        const char *name = nikss_action_param_get_name(ctx, entry, ap);
        uint32_t ref_value = 0;
        size_t ref_len = nikss_action_param_get_data_len(ap);
        json_t *ref = json_object();
        if (ref_len > sizeof(ref_value) || ref == NULL) {
            json_decref(ref);
            json_decref(refs_root);
            nikss_action_param_free(ap);
            return NULL;
        }
        memcpy(&ref_value, nikss_action_param_get_data(ap), ref_len);

        if (name != NULL) {
            json_object_set_new(ref, "target", json_string(name));
        }
        if (nikss_action_param_is_group_reference(ap)) {
            json_object_set_new(ref, "group_ref", json_integer(ref_value));
        } else {
            json_object_set_new(ref, "member_ref", json_integer(ref_value));
        }
        json_array_append_new(refs_root, ref);

        nikss_action_param_free(ap);
    }

    return refs_root;
}

static json_t *create_json_entry_direct_counter(nikss_table_entry_ctx_t *ctx, nikss_table_entry_t *entry)
{
    json_t *counters_root = json_object();
    if (counters_root == NULL) {
        return NULL;
    }

    nikss_direct_counter_context_t *dc_ctx = NULL;
    while ((dc_ctx = nikss_direct_counter_get_next_ctx(ctx, entry)) != NULL) {
        nikss_counter_entry_t counter;
        int ret = nikss_direct_counter_get_entry(dc_ctx, entry, &counter);
        nikss_counter_type_t type = nikss_direct_counter_get_type(dc_ctx);
        const char *name = nikss_direct_counter_get_name(dc_ctx);

        json_t *counter_entry = json_object();

        if (ret != NO_ERROR || name == NULL || counter_entry == NULL) {
            json_decref(counters_root);
            json_decref(counter_entry);
            nikss_counter_entry_free(&counter);
            nikss_direct_counter_ctx_free(dc_ctx);
            return NULL;
        }

        ret = build_json_counter_value(counter_entry, &counter, type);
        nikss_counter_entry_free(&counter);
        if (ret != NO_ERROR) {
            json_decref(counter_entry);
            json_decref(counters_root);
            nikss_direct_counter_ctx_free(dc_ctx);
            return NULL;
        }

        ret = json_object_set_new(counters_root, name, counter_entry);
        nikss_direct_counter_ctx_free(dc_ctx);
        if (ret != 0) {
            json_decref(counter_entry);
            json_decref(counters_root);
            return NULL;
        }
    }

    return counters_root;
}

static json_t *create_json_entry_direct_meter(nikss_table_entry_ctx_t *ctx, nikss_table_entry_t *entry)
{
    json_t *meters_root = json_object();
    if (meters_root == NULL) {
        return NULL;
    }

    nikss_direct_meter_context_t *dm_ctx = NULL;
    while ((dm_ctx = nikss_direct_meter_get_next_ctx(ctx, entry)) != NULL) {
        nikss_meter_entry_t meter;
        const char *name = nikss_direct_meter_get_name(dm_ctx);
        int ret = nikss_direct_meter_get_entry(dm_ctx, entry, &meter);
        json_t *meter_entry = create_json_meter_config(&meter);

        nikss_meter_entry_free(&meter);

        if (name == NULL || ret != NO_ERROR || meter_entry == NULL) {
            json_decref(meters_root);
            json_decref(meter_entry);
            nikss_direct_meter_ctx_free(dm_ctx);
            return NULL;
        }

        ret = json_object_set_new(meters_root, name, meter_entry);
        nikss_direct_meter_ctx_free(dm_ctx);
        if (ret != 0) {
            json_decref(meters_root);
            json_decref(meter_entry);
            return NULL;
        }
    }

    return meters_root;
}

static json_t *create_json_entry(nikss_table_entry_ctx_t *ctx, nikss_table_entry_t *entry, bool is_default_entry)
{
    json_t *entry_root = json_object();
    if (entry_root == NULL) {
        return NULL;
    }

    if (!is_default_entry) {
        json_t *key = create_json_entry_key(entry);
        if (key == NULL) {
            json_decref(entry_root);
            return NULL;
        }
        json_object_set_new(entry_root, "key", key);

        if (nikss_table_entry_ctx_has_priority(ctx)) {
            json_object_set_new(entry_root,
                                "priority",
                                json_integer(nikss_table_entry_get_priority(entry)));
        }
    }

    if (nikss_table_entry_ctx_is_indirect(ctx)) {
        json_t *references = create_json_entry_references(ctx, entry);
        if (references == NULL) {
            json_decref(entry_root);
            return NULL;
        }
        json_object_set_new(entry_root, "references", references);
    } else {
        json_t *action = create_json_entry_action(ctx, entry);
        if (action == NULL) {
            json_decref(entry_root);
            return NULL;
        }
        json_object_set_new(entry_root, "action", action);

        json_t *counters = create_json_entry_direct_counter(ctx, entry);
        if (counters == NULL) {
            json_decref(entry_root);
            return NULL;
        }
        json_object_set_new(entry_root, "DirectCounter", counters);

        json_t *meters = create_json_entry_direct_meter(ctx, entry);
        if (meters == NULL) {
            json_decref(entry_root);
            return NULL;
        }
        json_object_set_new(entry_root, "DirectMeter", meters);
    }

    return entry_root;
}

static int build_json_table_metadata(nikss_table_entry_ctx_t *ctx, json_t *parent)
{
    if (nikss_table_entry_ctx_is_indirect(ctx)) {
        return NO_ERROR;
    }

    /* DirectCounter */

    json_t *direct_counters = json_object();
    if (direct_counters == NULL) {
        return ENOMEM;
    }

    nikss_direct_counter_context_t *dc_ctx = NULL;
    nikss_table_entry_t entry;
    nikss_table_entry_init(&entry);
    while ((dc_ctx = nikss_direct_counter_get_next_ctx(ctx, &entry)) != NULL) {
        nikss_counter_type_t type = nikss_direct_counter_get_type(dc_ctx);
        const char *name = nikss_direct_counter_get_name(dc_ctx);
        json_t *counter_entry = json_object();

        if (name == NULL || counter_entry == NULL) {
            json_decref(counter_entry);
            nikss_direct_counter_ctx_free(dc_ctx);
            continue;
        }

        build_json_counter_type(counter_entry, type);
        json_object_set_new(direct_counters, name, counter_entry);
        nikss_direct_counter_ctx_free(dc_ctx);
    }
    nikss_table_entry_free(&entry);

    json_object_set_new(parent, "DirectCounter", direct_counters);

    return NO_ERROR;
}

enum table_print_mode {
    PRINT_SINGLE_ENTRY,
    PRINT_WHOLE_TABLE,
    PRINT_DEFAULT_ENTRY
};

static int print_json_table(nikss_table_entry_ctx_t *ctx, nikss_table_entry_t *entry,
                            const char *table_name, enum table_print_mode mode)
{
    int ret = EINVAL;
    json_t *root = json_object();
    json_t *instance_name = json_object();
    json_t *entries = json_array();

    if (root == NULL || instance_name == NULL || entries == NULL) {
        fprintf(stderr, "failed to prepare JSON\n");
        ret = ENOMEM;
        goto clean_up;
    }

    if (json_object_set(root, table_name, instance_name)) {
        fprintf(stderr, "failed to add JSON key %s\n", table_name);
        goto clean_up;
    }

    if (mode == PRINT_SINGLE_ENTRY || mode == PRINT_WHOLE_TABLE) {
        json_object_set(instance_name, "entries", entries);
    }

    if (entry != NULL && mode == PRINT_SINGLE_ENTRY) {
        json_t *parsed_entry = create_json_entry(ctx, entry, false);
        if (parsed_entry == NULL) {
            fprintf(stderr, "failed to create table JSON entry\n");
            goto clean_up;
        }
        json_array_append_new(entries, parsed_entry);
    }

    if (mode == PRINT_WHOLE_TABLE) {
        nikss_table_entry_t *current_entry = NULL;
        while ((current_entry = nikss_table_entry_get_next(ctx)) != NULL) {
            json_t *parsed_entry = create_json_entry(ctx, current_entry, false);
            if (parsed_entry == NULL) {
                fprintf(stderr, "failed to create table JSON entry\n");
                goto clean_up;
            }
            json_array_append_new(entries, parsed_entry);
            nikss_table_entry_free(current_entry);
        }
    }

    if (mode == PRINT_DEFAULT_ENTRY || mode == PRINT_WHOLE_TABLE) {
        nikss_table_entry_t default_entry;
        nikss_table_entry_init(&default_entry);

        if (nikss_table_entry_ctx_is_indirect(ctx) == false
            && nikss_table_entry_get_default_entry(ctx, &default_entry) == NO_ERROR) {
            json_t *parsed_entry = create_json_entry(ctx, &default_entry, true);
            if (parsed_entry == NULL) {
                fprintf(stderr, "failed to create table JSON default entry\n");
                goto clean_up;
            }
            json_object_set_new(instance_name, "default_action", parsed_entry);
        }
        nikss_table_entry_free(&default_entry);
    }

    if (build_json_table_metadata(ctx, instance_name) != NO_ERROR) {
        fprintf(stderr, "failed to create table JSON entry metadata\n");
        goto clean_up;
    }

    json_dumpf(root, stdout, JSON_INDENT(4) | JSON_ENSURE_ASCII);
    ret = NO_ERROR;

clean_up:
    json_decref(instance_name);
    json_decref(entries);
    json_decref(root);

    return ret;
}

/******************************************************************************
 * Command line table functions
 *****************************************************************************/

enum table_write_type_t {
    TABLE_ADD_NEW_ENTRY,
    TABLE_UPDATE_EXISTING_ENTRY,
    TABLE_SET_DEFAULT_ENTRY
};

int do_table_write(int argc, char **argv, enum table_write_type_t write_type)
{
    nikss_table_entry_t entry;
    nikss_table_entry_ctx_t ctx;
    nikss_action_t action;
    nikss_context_t nikss_ctx;
    int error_code = EPERM;

    nikss_context_init(&nikss_ctx);
    nikss_table_entry_ctx_init(&ctx);
    nikss_table_entry_init(&entry);
    nikss_action_init(&action);

    /* 0. Get the pipeline id */
    if (parse_pipeline_id(&argc, &argv, &nikss_ctx) != NO_ERROR) {
        goto clean_up;
    }

    /* no NEXT_ARG before in version from this file, so this check must be preserved */
    if (argc < 1) {
        fprintf(stderr, "too few parameters\n");
        goto clean_up;
    }

    /* 1. Get table */
    if (parse_dst_table(&argc, &argv, &nikss_ctx, &ctx, NULL, false) != NO_ERROR) {
        goto clean_up;
    }

    /* 2. Get action */
    bool can_ba_last_arg = write_type == TABLE_SET_DEFAULT_ENTRY ? true : false;
    if (parse_table_action(&argc, &argv, &ctx, &action, can_ba_last_arg) != NO_ERROR) {
        goto clean_up;
    }

    /* 3. Get key - default entry has no key */
    if (write_type != TABLE_SET_DEFAULT_ENTRY) {
        if (parse_table_key(&argc, &argv, &entry) != NO_ERROR) {
            goto clean_up;
        }
    }

    /* 4. Get action parameters */
    if (parse_action_data(&argc, &argv, &ctx, &entry, &action) != NO_ERROR) {
        goto clean_up;
    }

    /* 5. Get entry priority - not applicable to default entry */
    if (write_type != TABLE_SET_DEFAULT_ENTRY) {
        if (parse_entry_priority(&argc, &argv, &entry) != NO_ERROR) {
            goto clean_up;
        }
    }

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    nikss_table_entry_action(&entry, &action);

    if (write_type == TABLE_ADD_NEW_ENTRY) {
        error_code = nikss_table_entry_add(&ctx, &entry);
    } else if (write_type == TABLE_UPDATE_EXISTING_ENTRY) {
        error_code = nikss_table_entry_update(&ctx, &entry);
    } else if (write_type == TABLE_SET_DEFAULT_ENTRY) {
        error_code = nikss_table_entry_set_default_entry(&ctx, &entry);
    }

clean_up:
    nikss_action_free(&action);
    nikss_table_entry_free(&entry);
    nikss_table_entry_ctx_free(&ctx);
    nikss_context_free(&nikss_ctx);

    return error_code;
}

int do_table_add(int argc, char **argv)
{
    return do_table_write(argc, argv, TABLE_ADD_NEW_ENTRY);
}

int do_table_update(int argc, char **argv)
{
    return do_table_write(argc, argv, TABLE_UPDATE_EXISTING_ENTRY);
}

int do_table_delete(int argc, char **argv)
{
    nikss_table_entry_t entry;
    nikss_table_entry_ctx_t ctx;
    nikss_context_t nikss_ctx;
    int error_code = EPERM;

    nikss_context_init(&nikss_ctx);
    nikss_table_entry_ctx_init(&ctx);
    nikss_table_entry_init(&entry);

    /* 0. Get the pipeline id */
    if (parse_pipeline_id(&argc, &argv, &nikss_ctx) != NO_ERROR) {
        goto clean_up;
    }

    /* no NEXT_ARG before in version from this file, so this check must be preserved */
    if (argc < 1) {
        fprintf(stderr, "too few parameters\n");
        goto clean_up;
    }

    /* 1. Get table */
    if (parse_dst_table(&argc, &argv, &nikss_ctx, &ctx, NULL, true) != NO_ERROR) {
        goto clean_up;
    }

    /* 2. Get key */
    if (parse_table_key(&argc, &argv, &entry) != NO_ERROR) {
        goto clean_up;
    }

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    error_code = nikss_table_entry_del(&ctx, &entry);

clean_up:
    nikss_table_entry_free(&entry);
    nikss_table_entry_ctx_free(&ctx);
    nikss_context_free(&nikss_ctx);

    return error_code;
}

static int do_table_default_get(int argc, char **argv)
{
    nikss_table_entry_ctx_t ctx;
    nikss_context_t nikss_ctx;
    int error_code = EPERM;
    const char *table_name = NULL;

    nikss_context_init(&nikss_ctx);
    nikss_table_entry_ctx_init(&ctx);

    /* 0. Get the pipeline id */
    if (parse_pipeline_id(&argc, &argv, &nikss_ctx) != NO_ERROR) {
        goto clean_up;
    }

    /* 1. Get table */
    if (parse_dst_table(&argc, &argv, &nikss_ctx, &ctx, &table_name, true) != NO_ERROR) {
        goto clean_up;
    }

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    error_code = print_json_table(&ctx, NULL, table_name, PRINT_DEFAULT_ENTRY);

clean_up:
    nikss_table_entry_ctx_free(&ctx);
    nikss_context_free(&nikss_ctx);

    return error_code;
}

int do_table_default(int argc, char **argv)
{
    if (is_keyword(*argv, "set")) {
        NEXT_ARG();
        return do_table_write(argc, argv, TABLE_SET_DEFAULT_ENTRY);
    }
    if (is_keyword(*argv, "get")) {
        NEXT_ARG_RET();
        return do_table_default_get(argc, argv);
    }

    if (*argv != NULL) {
        fprintf(stderr, "%s: unknown keyword\n", *argv);
    }
    return do_table_help(argc, argv);
}

int do_table_get(int argc, char **argv)
{
    nikss_table_entry_t entry;
    nikss_table_entry_ctx_t ctx;
    nikss_context_t nikss_ctx;
    int error_code = EPERM;
    const char *table_name = NULL;
    enum table_print_mode print_mode = PRINT_WHOLE_TABLE;

    nikss_context_init(&nikss_ctx);
    nikss_table_entry_ctx_init(&ctx);
    nikss_table_entry_init(&entry);

    /* 0. Get the pipeline id */
    if (parse_pipeline_id(&argc, &argv, &nikss_ctx) != NO_ERROR) {
        goto clean_up;
    }

    /* 1. Get table */
    if (parse_dst_table(&argc, &argv, &nikss_ctx, &ctx, &table_name, true) != NO_ERROR) {
        goto clean_up;
    }

    /* 2. Check if table is indirect */
    if (parse_table_type(&argc, &argv, &ctx) != NO_ERROR) {
        goto clean_up;
    }

    /* 3. Get key */
    bool key_provided = (argc >= 1 && is_keyword(*argv, "key"));
    if (key_provided) {
        print_mode = PRINT_SINGLE_ENTRY;
        if (parse_table_key(&argc, &argv, &entry) != NO_ERROR) {
            goto clean_up;
        }
    }

    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", *argv);
        goto clean_up;
    }

    if (key_provided) {
        error_code = nikss_table_entry_get(&ctx, &entry);
        if (error_code != NO_ERROR) {
            goto clean_up;
        }
    }
    error_code = print_json_table(&ctx, &entry, table_name, print_mode);

clean_up:
    nikss_table_entry_free(&entry);
    nikss_table_entry_ctx_free(&ctx);
    nikss_context_free(&nikss_ctx);

    return error_code;
}

int do_table_help(int argc, char **argv)
{
    (void) argc; (void) argv;

    fprintf(stderr,
            "Usage: %1$s table add pipe ID TABLE_NAME action ACTION key MATCH_KEY [data ACTION_PARAMS] [priority PRIORITY]\n"
            "       %1$s table add pipe ID TABLE_NAME ref key MATCH_KEY data ACTION_REFS [priority PRIORITY]\n"
            "       %1$s table update pipe ID TABLE_NAME action ACTION key MATCH_KEY [data ACTION_PARAMS] [priority PRIORITY]\n"
            "       %1$s table delete pipe ID TABLE_NAME [key MATCH_KEY]\n"
            "       %1$s table get pipe ID TABLE_NAME [ref] [key MATCH_KEY]\n"
            "       %1$s table default set pipe ID TABLE_NAME action ACTION [data ACTION_PARAMS]\n"
            "       %1$s table default get pipe ID TABLE_NAME\n"
            /* Support for this one might be preserved, but makes no sense, because indirect tables
             * has no default entry. In other words we do not forbid this syntax explicitly.
             * "       %1$s table default pipe ID TABLE_NAME ref data ACTION_REFS\n" */
            "\n"
            "       ACTION := { id ACTION_ID | name ACTION_NAME }\n"
            "       ACTION_REFS := { MEMBER_REF | group GROUP_REF } \n"
            "       MATCH_KEY := { EXACT_KEY | LPM_KEY | RANGE_KEY | TERNARY_KEY | none }\n"
            "       EXACT_KEY := { DATA }\n"
            "       LPM_KEY := { DATA/PREFIX_LEN }\n"
            /* note: simple_switch_CLI uses '->' for range match, but this is
             *   harder to write in a CLI (needs an escape sequence) */
            "       RANGE_KEY := { DATA_MIN..DATA_MAX }\n"
            /* note: by default '&&&' is used but it also will require
             *   an escape sequence in a CLI, so lets use '^' instead */
            "       TERNARY_KEY := { DATA^MASK }\n"
            "       ACTION_PARAMS := { DATA | counter COUNTER_NAME COUNTER_VALUE | meter METER_NAME METER_VALUE }\n"
            "       COUNTER_VALUE := { BYTES | PACKETS | BYTES:PACKETS }\n"
            "       METER_VALUE := { PIR:PBS CIR:CBS }\n"
            "",
            program_name);
    return 0;
}
