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

#ifndef __PRECTL_VALUE_SET_H_
#define __PRECTL_VALUE_SET_H_

#include "common.h"

int do_value_set_help(int argc, char **argv);
int do_value_set_get(int argc, char **argv);
int do_value_set_delete(int argc, char **argv);
int do_value_set_insert(int argc, char **argv);

static const struct cmd value_set_cmds[] = {
        {"help", do_value_set_help},
        {"get",  do_value_set_get},
        {"delete",  do_value_set_delete},
        {"insert",  do_value_set_insert},
        {0}
};

#endif /* __PRECTL_VALUE_SET_H_ */
