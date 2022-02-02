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

#ifndef __PSABPFCTL_CLONE_SESSION_H
#define __PSABPFCTL_CLONE_SESSION_H

#include "common.h"

#define MAX_CLONE_SESSION_MEMBERS 64

int do_create(int argc, char **argv);
int do_delete(int argc, char **argv);
int do_add_member(int argc, char **argv);
int do_del_member(int argc, char **argv);
int do_clone_session_help(int argc, char **argv);

static const struct cmd clone_session_cmds[] = {
        {"help",       do_clone_session_help},
        {"create",     do_create},
        {"delete",     do_delete},
        {"add-member", do_add_member},
        {"del-member", do_del_member},
        {0}
};

#endif //__PSABPFCTL_CLONE_SESSION_H
