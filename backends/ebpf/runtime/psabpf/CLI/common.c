
#include <string.h>

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