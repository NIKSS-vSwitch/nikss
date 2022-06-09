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

#ifndef P4C_ACTION_SELECTOR_H
#define P4C_ACTION_SELECTOR_H

#include "common.h"

int do_action_selector_add_member(int argc, char **argv);
int do_action_selector_delete_member(int argc, char **argv);
int do_action_selector_update_member(int argc, char **argv);
int do_action_selector_create_group(int argc, char **argv);
int do_action_selector_delete_group(int argc, char **argv);
int do_action_selector_add_to_group(int argc, char **argv);
int do_action_selector_delete_from_group(int argc, char **argv);
int do_action_selector_default_group_action(int argc, char **argv);
int do_action_selector_get(int argc, char **argv);

int do_action_selector_help(int argc, char **argv);

static const struct cmd action_selector_cmds[] = {
        {"help",                 do_action_selector_help},
        {"add_member",           do_action_selector_add_member},
        {"delete_member",        do_action_selector_delete_member},
        {"update_member",        do_action_selector_update_member},
        {"create_group",         do_action_selector_create_group},
        {"delete_group",         do_action_selector_delete_group},
        {"add_to_group",         do_action_selector_add_to_group},
        {"delete_from_group",    do_action_selector_delete_from_group},
        {"default_group_action", do_action_selector_default_group_action},
        {"get",                  do_action_selector_get},
        {0}
};

#endif  //P4C_ACTION_SELECTOR_H
