#ifndef P4C_ACTION_SELECTOR_H
#define P4C_ACTION_SELECTOR_H

#include "common.h"

int do_action_selector_add_member(int argc, char **argv);
int do_action_selector_delete_member(int argc, char **argv);
int do_action_selector_update_member(int argc, char **argv);
int do_action_selector_create_group(int argc, char **argv);
int do_action_selector_delete_group(int argc, char **argv);
int do_action_selector_add_to_group(int argc, char **argv);
int do_action_selector_delete_from_group(int argc, char **argv);
int do_action_selector_default_group_action(int argc, char **argv);

int do_action_selector_help(int argc, char **argv);

static const struct cmd action_selector_cmds[] = {
        {"add_member",           do_action_selector_add_member},
        {"delete_member",        do_action_selector_delete_member},
        {"update_member",        do_action_selector_update_member},
        {"create_group",         do_action_selector_create_group},
        {"delete_group",         do_action_selector_delete_group},
        {"add_to_group",         do_action_selector_add_to_group},
        {"delete_from_group",    do_action_selector_delete_from_group},
        {"default_group_action", do_action_selector_default_group_action},
        {"help",                 do_action_selector_help},
        {0}
};

#endif  //P4C_ACTION_SELECTOR_H
