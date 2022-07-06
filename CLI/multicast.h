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

#ifndef __PRECTL_MULTICAST_H
#define __PRECTL_MULTICAST_H

#include "common.h"

int do_multicast_create_group(int argc, char **argv);
int do_multicast_delete_group(int argc, char **argv);
int do_multicast_add_group_member(int argc, char **argv);
int do_multicast_del_group_member(int argc, char **argv);
int do_multicast_get(int argc, char **argv);
int do_multicast_help(int argc, char **argv);


static const struct cmd multicast_cmds[] = {
        {"help",       do_multicast_help},
        {"create",     do_multicast_create_group},
        {"delete",     do_multicast_delete_group},
        {"add-member", do_multicast_add_group_member},
        {"del-member", do_multicast_del_group_member},
        {"get",        do_multicast_get},
        {0}
};

#endif  /* __PRECTL_MULTICAST_H */
