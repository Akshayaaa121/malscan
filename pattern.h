/*
 * pattern.h
 * ---------------------------------------------------------------------------
 * Represents a single search pattern (one "term" inside a rule) and the
 * matching engines used to find it inside the scanned file's raw bytes.
 *
 * A pattern is either:
 *   - a quoted string literal:      "some text"
 *   - a case-insensitive string:    "some text" nocase
 *   - a hex byte pattern:           {4D 5A 90 ??}   ('??' = wildcard byte)
 * ---------------------------------------------------------------------------
 */
#ifndef MALSCAN_PATTERN_H
#define MALSCAN_PATTERN_H

#include <stddef.h>

typedef struct {
    unsigned char *bytes;
    unsigned char *mask;      /* mask[i]==1: byte must match; 0: wildcard */
    size_t len;
    int nocase;               /* 1 if this is a case-insensitive string pattern */
    int has_wildcard;         /* 1 if any mask[i] == 0 */
} Pattern;

/* Releases the buffers owned by `p` and zeroes it out. */
void pattern_free(Pattern *p);

/* Parses a quoted string literal starting at *p (pointing at the
 * opening '"'). Handles escapes: \" \\ \n \t \r \xHH.
 * On success, advances *p past the closing quote, returns a malloc'd
 * raw byte buffer, and sets *out_len. Returns NULL on malformed input
 * (unterminated string). */
unsigned char *parse_quoted_string(const char **p, size_t *out_len);

/* Parses a hex byte pattern starting at *p (pointing at '{'). Bytes
 * are two hex digits separated by whitespace; "??" denotes a wildcard
 * byte. On success, advances *p past the closing '}', fills
 * *out_bytes / *out_mask (both malloc'd, caller must free) and *out_len.
 * Returns 0 on success, -1 on malformed input. */
int parse_hex_pattern(const char **p, unsigned char **out_bytes,
                       unsigned char **out_mask, size_t *out_len);

/* Searches for `pat` anywhere inside hay[0..hlen). Automatically
 * dispatches to the fastest applicable strategy:
 *   - Boyer-Moore-Horspool for exact, case-sensitive patterns
 *   - a direct wildcard/case-fold-aware scan otherwise
 * Returns 1 if found, 0 otherwise. */
int pattern_matches(const unsigned char *hay, size_t hlen, const Pattern *pat);

#endif /* MALSCAN_PATTERN_H */
