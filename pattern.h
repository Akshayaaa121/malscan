
#ifndef MALSCAN_PATTERN_H
#define MALSCAN_PATTERN_H

#include <stddef.h>

typedef struct {
    unsigned char *bytes;
    unsigned char *mask;      
    size_t len;
    int nocase;               
    int has_wildcard;        
} Pattern;

void pattern_free(Pattern *p);

unsigned char *parse_quoted_string(const char **p, size_t *out_len);


int parse_hex_pattern(const char **p, unsigned char **out_bytes,
                       unsigned char **out_mask, size_t *out_len);

int pattern_matches(const unsigned char *hay, size_t hlen, const Pattern *pat);

#endif 
