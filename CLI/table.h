#ifndef __PRECTL_TABLE_H
#define __PRECTL_TABLE_H

#include "common.h"

int do_table_add(int argc, char **argv);
int do_table_update(int argc, char **argv);
int do_table_delete(int argc, char **argv);
int do_table_help(int argc, char **argv);

static const struct cmd table_cmds[] = {
        {"help",   do_table_help},
        {"add",    do_table_add},
        {"update", do_table_update},
        {"delete", do_table_delete},
        {0}
};

#endif  //__PRECTL_TABLE_H
