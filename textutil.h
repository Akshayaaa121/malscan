/*
 * textutil.h
 * ---------------------------------------------------------------------------
 * Small, dependency-free text helpers shared by the rule-line tokenizer
 * (rule.c) and the rule-file section parser (malwaredef.c).
 * ---------------------------------------------------------------------------
 */
#ifndef MALSCAN_TEXTUTIL_H
#define MALSCAN_TEXTUTIL_H

/* Advances *p past any whitespace characters. */
void skip_spaces(const char **p);

/* Case-insensitive keyword match at *p. If `kw` matches at *p AND is
 * followed by a non-alphanumeric/non-underscore character (a proper
 * word boundary), advances *p past the keyword and any trailing
 * whitespace, then returns 1. Otherwise leaves *p unchanged and
 * returns 0. */
int match_keyword(const char **p, const char *kw);

/* Trims leading/trailing whitespace from `s` in place (mutates `s` by
 * NUL-terminating early and returns a pointer possibly past the
 * original start). */
char *trim(char *s);

#endif /* MALSCAN_TEXTUTIL_H */
