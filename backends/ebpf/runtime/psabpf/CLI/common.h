#include <stdbool.h>
#include "../include/psabpf.h"

#ifndef P4C_COMMON_H
#define P4C_COMMON_H

#define NEXT_ARG()	({ argc--; argv++; if (argc < 0) fprintf(stderr, "too few parameters\n"); })
#define NEXT_ARGP()	({ (*argc)--; (*argv)++; if (*argc < 0) fprintf(stderr, "too few parameters\n"); })

#define NEXT_ARG_EXIT()  ({ argc--; argv++; if (argc < 1) { fprintf(stderr, "too few parameters\n"); exit(1); }})
#define NEXT_ARGP_EXIT() ({ (*argc)--; (*argv)++; if ((*argc) < 1) { fprintf(stderr, "too few parameters\n"); exit(1); }})


struct cmd {
    const char *cmd;
    int (*func)(int argc, char **argv);
};

bool is_keyword(const char *word, const char *str);

int parse_pipeline_id(int *argc, char ***argv, psabpf_context_t * psabpf_ctx);

extern const char *program_name;

#endif //P4C_COMMON_H
