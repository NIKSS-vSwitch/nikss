#ifndef __PRECTL_CLONE_SESSION_H
#define __PRECTL_CLONE_SESSION_H

#include "common.h"

#define MAX_CLONE_SESSION_MEMBERS 64

int do_create(int argc, char **argv);
int do_delete(int argc, char **argv);
int do_add_member(int argc, char **argv);
int do_del_member(int argc, char **argv);

static const struct cmd clone_session_cmds[] = {
        {"create",     do_create},
        {"delete",     do_delete},
        {"add-member", do_add_member},
        {"del-member", do_del_member},
        {0}
};

#endif //__PRECTL_CLONE_SESSION_H
