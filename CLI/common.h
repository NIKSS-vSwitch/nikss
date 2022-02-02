#include <stdbool.h>
#include "../include/psabpf.h"
#include <arpa/inet.h>
#include <ctype.h>

#ifndef P4C_COMMON_H
#define P4C_COMMON_H

#define NEXT_ARG()	({ argc--; argv++; if (argc < 0) fprintf(stderr, "too few parameters\n"); })
#define NEXT_ARGP()	({ (*argc)--; (*argv)++; if (*argc < 0) fprintf(stderr, "too few parameters\n"); })

#define NEXT_ARG_EXIT()  ({ argc--; argv++; if (argc < 1) { fprintf(stderr, "too few parameters\n"); exit(1); }})
#define NEXT_ARGP_EXIT() ({ (*argc)--; (*argv)++; if ((*argc) < 1) { fprintf(stderr, "too few parameters\n"); exit(1); }})

#define NEXT_ARG_RET()  ({ argc--; argv++; if (argc < 1) { fprintf(stderr, "too few parameters\n"); return 1; }})
#define NEXT_ARGP_RET()  ({ (*argc)--; (*argv)++; if ((*argc) < 1) { fprintf(stderr, "too few parameters\n"); return 1; }})

struct cmd {
    const char *cmd;
    int (*func)(int argc, char **argv);
};

bool is_keyword(const char *word, const char *str);

int parse_pipeline_id(int *argc, char ***argv, psabpf_context_t * psabpf_ctx);

extern const char *program_name;

enum destination_ctx_type_t {
    CTX_MATCH_KEY,
    CTX_MATCH_KEY_TERNARY_MASK,
    CTX_ACTION_DATA,
    CTX_METER_INDEX,
};

int translate_data_to_bytes(const char *data, void *ctx, enum destination_ctx_type_t ctx_type);
char * convert_data_to_hexstr(const void *data, size_t len);

#endif //P4C_COMMON_H
