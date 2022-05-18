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

#ifndef __PRECTL_REGISTER_H
#define __PRECTL_REGISTER_H

#include "common.h"

int do_register_get(int argc, char **argv);
int do_register_set(int argc, char **argv);
int do_register_help(int argc, char **argv);

static const struct cmd register_cmds[] = {
        {"help", do_register_help},
        {"get", do_register_get},
        {"set", do_register_set},
        {0}
};

#endif  /* __PRECTL_REGISTER_H */
