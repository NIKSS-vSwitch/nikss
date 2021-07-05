#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "common.h"

bool is_keyword(const char *word, const char *str)
{
    if (!word)
        return false;

    if (strlen(word) < strlen(str)) {
        return false;
    }

    return !memcmp(str, word, strlen(str));
}

int parse_pipeline_id(int *argc, char ***argv, psabpf_context_t * psabpf_ctx)
{
    if (*argc < 2) {
        fprintf(stderr, "too few parameters\n");
        return -1;
    }

    if (!is_keyword(**argv, "pipe")) {
        fprintf(stderr, "expected 'pipe' keyword\n");
        return EINVAL;
    }
    NEXT_ARGP();

    char *endptr;
    psabpf_pipeline_id_t id = strtoul(**argv, &endptr, 0);
    if (*endptr) {
        fprintf(stderr, "can't parse '%s'\n", **argv);
        return EINVAL;
    }
    psabpf_context_set_pipeline(psabpf_ctx, id);

    NEXT_ARGP();

    return NO_ERROR;
}
