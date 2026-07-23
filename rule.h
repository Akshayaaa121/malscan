/*
 * rule.h
 * ---------------------------------------------------------------------------
 * A Rule represents one line from a [rules] section: a boolean
 * expression built from one or more Terms, combined with not/and/or.
 * Precedence: NOT binds tightest, then AND, then OR, evaluated left
 * to right (no parenthesized grouping in this version).
 * ---------------------------------------------------------------------------
 */
#ifndef MALSCAN_RULE_H
#define MALSCAN_RULE_H

#include <stddef.h>
#include "pattern.h"

typedef struct {
    Pattern pattern;
    int negate; /* 1 if preceded by "not" */
} Term;

typedef enum { OP_AND, OP_OR } BoolOp;

typedef struct {
    Term *terms;
    int term_count;
    BoolOp *ops;    /* term_count - 1 operators; ops[i] joins terms[i], terms[i+1] */
    char *raw_text; /* original rule line text, kept for reporting matches */
} Rule;

/* Releases everything owned by `r` (patterns, arrays, raw text). */
void rule_free(Rule *r);

/* Parses one rule line (e.g. `"a" and not {AA BB} nocase`) into `rule`.
 * `filepath`/`lineno` are used only for error messages. Returns 0 on
 * success, -1 on a parse error (already printed to stderr). */
int parse_rule_line(const char *line, Rule *rule, const char *filepath, int lineno);

/* Evaluates `rule`'s boolean expression against the target file's raw
 * bytes hay[0..hlen). Returns 1 if the rule matches, 0 otherwise. */
int eval_rule(const Rule *rule, const unsigned char *hay, size_t hlen);

#endif /* MALSCAN_RULE_H */
