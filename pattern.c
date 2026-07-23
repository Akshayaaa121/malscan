#include "platform.h"
#include "pattern.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

void pattern_free(Pattern *p) {
    free(p->bytes);
    free(p->mask);
    p->bytes = NULL;
    p->mask = NULL;
    p->len = 0;
}

unsigned char *parse_quoted_string(const char **p, size_t *out_len) {
    const char *s = *p;
    if (*s != '"') return NULL;
    s++;

    unsigned char *buf = (unsigned char *)malloc(strlen(s) + 1);
    if (!buf) return NULL;
    size_t n = 0;

    while (*s && *s != '"') {
        if (*s == '\\' && *(s + 1) != '\0') {
            s++;
            switch (*s) {
                case 'n': buf[n++] = '\n'; s++; break;
                case 't': buf[n++] = '\t'; s++; break;
                case 'r': buf[n++] = '\r'; s++; break;
                case '\\': buf[n++] = '\\'; s++; break;
                case '"': buf[n++] = '"'; s++; break;
                case 'x': {
                    s++;
                    int hi = -1, lo = -1;
                    if (isxdigit((unsigned char)s[0]) && isxdigit((unsigned char)s[1])) {
                        char tmp[3] = { s[0], s[1], '\0' };
                        hi = (int)strtol(tmp, NULL, 16);
                        lo = 0; 
                        s += 2;
                    }
                    if (lo == -1) {
                        buf[n++] = 'x'; 
                    } else {
                        buf[n++] = (unsigned char)hi;
                    }
                    break;
                }
                default:
                    buf[n++] = (unsigned char)*s;
                    s++;
                    break;
            }
        } else {
            buf[n++] = (unsigned char)*s;
            s++;
        }
    }

    if (*s != '"') {
        free(buf);
        return NULL; /* unterminated string */
    }
    s++;

    *p = s;
    *out_len = n;
    return buf;
}

int parse_hex_pattern(const char **p, unsigned char **out_bytes,
                       unsigned char **out_mask, size_t *out_len) {
    const char *s = *p;
    if (*s != '{') return -1;
    s++;

    size_t cap = 32, n = 0;
    unsigned char *bytes = (unsigned char *)malloc(cap);
    unsigned char *mask = (unsigned char *)malloc(cap);
    if (!bytes || !mask) { free(bytes); free(mask); return -1; }

    while (*s && *s != '}') {
        if (isspace((unsigned char)*s)) { s++; continue; }

        if (n >= cap) {
            cap *= 2;
            unsigned char *nb = (unsigned char *)realloc(bytes, cap);
            if (!nb) { free(bytes); free(mask); return -1; }
            bytes = nb;
            unsigned char *nm = (unsigned char *)realloc(mask, cap);
            if (!nm) { free(bytes); free(mask); return -1; }
            mask = nm;
        }

        if (s[0] == '?' && s[1] == '?') {
            bytes[n] = 0x00;
            mask[n] = 0;
            n++;
            s += 2;
        } else if (isxdigit((unsigned char)s[0]) && isxdigit((unsigned char)s[1])) {
            char tmp[3] = { s[0], s[1], '\0' };
            bytes[n] = (unsigned char)strtol(tmp, NULL, 16);
            mask[n] = 1;
            n++;
            s += 2;
        } else {
            free(bytes);
            free(mask);
            return -1;
        }
    }

    if (*s != '}') { free(bytes); free(mask); return -1; }
    s++;

    *p = s;
    *out_bytes = bytes;
    *out_mask = mask;
    *out_len = n;
    return 0;
}


static int bmh_search(const unsigned char *hay, size_t hlen,
                       const unsigned char *pat, size_t plen) {
    if (plen == 0) return 1;
    if (plen > hlen) return 0;

    size_t skip[256];
    for (int i = 0; i < 256; i++) skip[i] = plen;
    for (size_t i = 0; i < plen - 1; i++) skip[pat[i]] = plen - 1 - i;

    size_t pos = 0;
    while (pos <= hlen - plen) {
        size_t j = plen - 1;
        while (hay[pos + j] == pat[j]) {
            if (j == 0) return 1;
            j--;
        }
        pos += skip[hay[pos + plen - 1]];
    }
    return 0;
}

static inline unsigned char lower_byte(unsigned char c) {
    return (unsigned char)tolower(c);
}


static int generic_search(const unsigned char *hay, size_t hlen, const Pattern *pat) {
    size_t plen = pat->len;
    if (plen == 0) return 1;
    if (plen > hlen) return 0;

    for (size_t pos = 0; pos <= hlen - plen; pos++) {
        int ok = 1;
        for (size_t j = 0; j < plen; j++) {
            if (pat->mask[j] == 0) continue; 
            unsigned char h = hay[pos + j];
            unsigned char c = pat->bytes[j];
            if (pat->nocase) {
                if (lower_byte(h) != lower_byte(c)) { ok = 0; break; }
            } else {
                if (h != c) { ok = 0; break; }
            }
        }
        if (ok) return 1;
    }
    return 0;
}

int pattern_matches(const unsigned char *hay, size_t hlen, const Pattern *pat) {
    if (pat->has_wildcard || pat->nocase) {
        return generic_search(hay, hlen, pat);
    }
    return bmh_search(hay, hlen, pat->bytes, pat->len);
}
