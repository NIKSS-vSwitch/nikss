#include <getopt.h>
#include <stdio.h>

#include "CLI/common.h"
#include "CLI/clone_session.h"
#include "CLI/pipeline.h"

/*
 * Formats:
 * psabpf-ctl pipeline load <path>
 * psabpf-ctl pipeline unload <handle>
 * psabpf-ctl clone-session create id 5
 * psabpf-ctl clone-session delete id 5
 * psabpf-ctl clone-session add-member id 5 egress-port 1 instance 1
 * psabpf-ctl clone-session del-member id 5 egress-port 1 instance 1
 */

static int last_argc;
static char **last_argv;
static int (*last_do_help)(int argc, char **argv);
static const char *bin_name;

int cmd_select(const struct cmd *cmds, int argc, char **argv,
               int (*help)(int argc, char **argv))
{
    unsigned int i;

    last_argc = argc;
    last_argv = argv;
    last_do_help = help;

    if (argc < 1 && cmds[0].func)
        return cmds[0].func(argc, argv);

    for (i = 0; cmds[i].cmd; i++) {
        if (is_keyword(*argv, cmds[i].cmd)) {
            if (!cmds[i].func) {
                return -1;
            }
            return cmds[i].func(argc - 1, argv + 1);
        }
    }

    help(argc - 1, argv + 1);

    return -1;
}

static int do_help(int argc, char **argv)
{
    fprintf(stderr,
            "Usage: %s OBJECT COMMAND { id OBJECT_ID | help }\n"
            "       %s help\n"
            "\n"
            "       OBJECT := { clone-session | multicast-group }\n"
            "       COMMAND := { create | delete | add-member | del-member }\n"
            "",
            bin_name, bin_name);

    return 0;
}

static int do_clone_session(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "too few parameters for clone-session\n");
        return -1;
    }

    return cmd_select(clone_session_cmds, argc, argv, do_help);
}

static int do_pipeline(int argc, char **argv)
{
    return cmd_select(pipeline_cmds, argc, argv, do_help);
}

static const struct cmd cmds[] = {
        { "help",	        do_help },
        { "clone-session",	do_clone_session },
        { "pipeline",      do_pipeline },
        { 0 }
};

int main(int argc, char **argv)
{
    int ret;
    bin_name = argv[0];

    argc -= optind;
    argv += optind;

    return cmd_select(cmds, argc, argv, do_help);
}