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

#ifndef __PSABPFCTL_PIPELINE_H
#define __PSABPFCTL_PIPELINE_H

#include "common.h"

int do_pipeline_help(int argc, char **argv);
int do_pipeline_load(int argc, char **argv);
int do_pipeline_unload(int argc, char **argv);
int do_pipeline_port_add(int argc, char **argv);
int do_pipeline_port_del(int argc, char **argv);
int do_pipeline_show(int argc, char **argv);

static const struct cmd pipeline_cmds[] = {
        {"help",     do_pipeline_help },
        {"load",     do_pipeline_load },
        {"unload",   do_pipeline_unload },
        {"show",     do_pipeline_show },
        {0}
};

#endif // __PSABPFCTL_PIPELINE_H
