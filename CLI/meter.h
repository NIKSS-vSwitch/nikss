#ifndef __PSABPFCTL_METER_H
#define __PSABPFCTL_METER_H

#include "common.h"

int do_meter_get(int argc, char **argv);
int do_meter_update(int argc, char **argv);
int do_meter_reset(int argc, char **argv);
int do_meter_help(int argc, char **argv);

static const struct cmd meter_cmds[] = {
        {"help",   do_meter_help},
        {"get",    do_meter_get},
        {"update", do_meter_update},
        {"reset",  do_meter_reset},
        {0}
};

#endif // __PSABPFCTL_METER_H