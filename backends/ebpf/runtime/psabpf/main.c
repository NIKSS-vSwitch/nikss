#include <getopt.h>
#include <stdio.h>

#include "CLI/common.h"
#include "CLI/clone_session.h"
#include "CLI/pipeline.h"
#include "CLI/table.h"

static int last_argc;
static char **last_argv;
static int (*last_do_help)(int argc, char **argv);
const char *program_name;

int cmd_select(const struct cmd *cmds, int argc, char **argv,
               int (*help)(int argc, char **argv))
{
    unsigned int i;

    last_argc = argc;
    last_argv = argv;
    last_do_help = help;

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
    fprintf(stderr,
            "Usage: %s [OPTIONS] OBJECT {COMMAND | help }\n"
            "       %s help\n"
            "\n"
            "       OBJECT := { clone-session | multicast-group | pipeline | table }\n"
            "       OPTIONS := {}\n"
            "",
            program_name, program_name);

    return 0;
}

static int do_clone_session(int argc, char **argv)
{
    if (argc < 3) {
        do_clone_session_help(argc, argv);
        return -1;
    }

    return cmd_select(clone_session_cmds, argc, argv, do_clone_session_help);
}

static int do_pipeline(int argc, char **argv)
{
    return cmd_select(pipeline_cmds, argc, argv, do_pipeline_help);
}

static int do_table(int argc, char **argv)
{
    return cmd_select(table_cmds, argc, argv, do_table_help);
}

static const struct cmd cmds[] = {
        { "help",	        do_help },
        { "clone-session",	do_clone_session },
        { "pipeline",       do_pipeline },
        { "table",          do_table },
        { 0 }
};

int main(int argc, char **argv)
{
    int ret;
    program_name = argv[0];

    // TODO: parse program options

    argc -= optind;
    argv += optind;

    return cmd_select(cmds, argc, argv, do_help);
}