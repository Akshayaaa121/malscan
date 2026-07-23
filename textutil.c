#include "platform.h"
#include "textutil.h"

#include <ctype.h>
#include <string.h>

void skip_spaces(const char **p) {
    while (isspace((unsigned char)**p)) (*p)++;
}

int match_keyword(const char **p, const char *kw) {
    const char *s = *p;
    size_t klen = strlen(kw);
    for (size_t i = 0; i < klen; i++) {
        if (tolower((unsigned char)s[i]) != tolower((unsigned char)kw[i])) return 0;
    }
    char after = s[klen];
    if (isalnum((unsigned char)after) || after == '_') return 0;

    *p = s + klen;
    skip_spaces(p);
    return 1;
}

char *trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}
