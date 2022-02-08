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

#include <getopt.h>
#include <stdio.h>

#include "CLI/common.h"
#include "CLI/clone_session.h"
#include "CLI/multicast.h"
#include "CLI/pipeline.h"
#include "CLI/table.h"
#include "CLI/action_selector.h"
#include "CLI/meter.h"
#include "CLI/digest.h"

const char *program_name;

int cmd_select(const struct cmd *cmds, int argc, char **argv,
               int (*help)(int, char **))
{
    unsigned int i;

    if (argc < 1)
        return help(argc, argv);

    for (i = 0; cmds[i].cmd; i++) {
        if (is_keyword(*argv, cmds[i].cmd)) {
            if (!cmds[i].func) {
                return -1;
            }
            return cmds[i].func(argc - 1, argv + 1);
        }
    }

    fprintf(stderr, "%s: unknown keyword\n", *argv);
    help(argc - 1, argv + 1);

    return -1;
}

static int do_help(int argc, char **argv)
{
    (void) argc; (void) argv;
    fprintf(stderr,
            "Usage: %s [OPTIONS] OBJECT {COMMAND | help }\n"
            "       %s help\n"
            "\n"
            "       OBJECT := { clone-session |\n"
            "                   multicast-group |\n"
            "                   pipeline |\n"
            "                   add-port |\n"
            "                   del-port |\n"
            "                   table |\n"
            "                   action-selector |\n"
            "                   meter |\n"
            "                   digest }\n"
            "       OPTIONS := {}\n"
            "",
            program_name, program_name);

    return 0;
}

static int do_pipeline(int argc, char **argv)
{
    return cmd_select(pipeline_cmds, argc, argv, do_pipeline_help);
}

static int do_port_add(int argc, char **argv)
{
    if (is_keyword(*argv, "help") || argc < 1)
        return do_pipeline_help(argc, argv);

    return do_pipeline_port_add(argc, argv);
}

static int do_port_del(int argc, char **argv)
{
    if (is_keyword(*argv, "help") || argc < 1)
        return do_pipeline_help(argc, argv);

    return do_pipeline_port_del(argc, argv);
}

static int do_clone_session(int argc, char **argv)
{
    if (argc < 2) {
        do_clone_session_help(argc, argv);
        return -1;
    }

    return cmd_select(clone_session_cmds, argc, argv, do_clone_session_help);
}

static int do_multicast(int argc, char **argv)
{
    return cmd_select(multicast_cmds, argc, argv, do_multicast_help);
}

static int do_table(int argc, char **argv)
{
    return cmd_select(table_cmds, argc, argv, do_table_help);
}

static int do_meter(int argc, char **argv)
{
    return cmd_select(meter_cmds, argc, argv, do_meter_help);
}

static int do_action_selector(int argc, char **argv)
{
    return cmd_select(action_selector_cmds, argc, argv, do_action_selector_help);
}

static int do_digest(int argc, char **argv)
{
    return cmd_select(digest_cmds, argc, argv, do_digest_help);
}

static const struct cmd cmds[] = {
        { "help",            do_help },
        { "pipeline",        do_pipeline },
        { "add-port",        do_port_add },
        { "del-port",        do_port_del },
        { "clone-session",   do_clone_session },
        { "multicast-group", do_multicast },
        { "table",           do_table },
        { "action-selector", do_action_selector },
        { "meter",           do_meter },
        { "digest",          do_digest },
        { 0 }
};

int main(int argc, char **argv)
{
    program_name = argv[0];

    // TODO: parse program options

    argc -= optind;
    argv += optind;

    return cmd_select(cmds, argc, argv, do_help);
}