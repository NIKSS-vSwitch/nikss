#ifndef __PSABPFCTL_PIPELINE_H
#define __PSABPFCTL_PIPELINE_H

#include "common.h"

int do_pipeline_help(int argc, char **argv);
int do_load(int argc, char **argv);
int do_unload(int argc, char **argv);
int do_port_add(int argc, char **argv);
int do_port_del(int argc, char **argv);

static const struct cmd pipeline_cmds[] = {
        {"help",     do_pipeline_help },
        {"load",     do_load },
        {"unload",   do_unload },
        {"add-port", do_port_add },
        {"del-port", do_port_del },
        {0}
};

#endif // __PSABPFCTL_PIPELINE_H
