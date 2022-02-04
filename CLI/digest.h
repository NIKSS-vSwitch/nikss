#ifndef __PRECTL_DIGEST_H
#define __PRECTL_DIGEST_H

#include "common.h"

int do_digest_get(int argc, char **argv);
int do_digest_help(int argc, char **argv);

static const struct cmd digest_cmds[] = {
        {"help", do_digest_help},
        {"get",  do_digest_get},
        {0}
};

#endif  /* __PRECTL_DIGEST_H */
