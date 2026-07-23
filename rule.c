#include "platform.h"
#include "rule.h"
#include "pattern.h"
#include "textutil.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void rule_free(Rule *r) {
    for (int i = 0; i < r->term_count; i++) {
        pattern_free(&r->terms[i].pattern);
    }
    free(r->terms);
    free(r->ops);
    free(r->raw_text);
    r->terms = NULL;
    r->ops = NULL;
    r->term_count = 0;
    r->raw_text = NULL;
}

int parse_rule_line(const char *line, Rule *rule, const char *filepath, int lineno) {
    memset(rule, 0, sizeof(*rule));
    rule->raw_text = strdup(line);

    int cap = 4;
    rule->terms = (Term *)malloc(sizeof(Term) * cap);
    rule->ops = (BoolOp *)malloc(sizeof(BoolOp) * cap);
    rule->term_count = 0;

    const char *p = line;
    skip_spaces(&p);

    int expect_term = 1;
    while (*p) {
        skip_spaces(&p);
        if (!*p) break;

        if (expect_term) {
            int negate = 0;
            while (match_keyword(&p, "not")) {
                negate = !negate;
            }

            Term t;
            memset(&t, 0, sizeof(t));
            t.negate = negate;

            if (*p == '"') {
                size_t slen = 0;
                unsigned char *sbytes = parse_quoted_string(&p, &slen);
                if (!sbytes) {
                    fprintf(stderr, "malscan: parse error in %s:%d - malformed string literal\n",
                            filepath, lineno);
                    free(rule->terms); free(rule->ops); free(rule->raw_text);
                    return -1;
                }
                t.pattern.bytes = sbytes;
                t.pattern.mask = (unsigned char *)malloc(slen > 0 ? slen : 1);
                for (size_t i = 0; i < slen; i++) t.pattern.mask[i] = 1;
                t.pattern.len = slen;
                t.pattern.has_wildcard = 0;

                skip_spaces(&p);
                if (match_keyword(&p, "nocase")) {
                    t.pattern.nocase = 1;
                } else {
                    t.pattern.nocase = 0;
                }
            } else if (*p == '{') {
                unsigned char *hbytes = NULL, *hmask = NULL;
                size_t hlen = 0;
                if (parse_hex_pattern(&p, &hbytes, &hmask, &hlen) != 0) {
                    fprintf(stderr, "malscan: parse error in %s:%d - malformed hex pattern\n",
                            filepath, lineno);
                    free(rule->terms); free(rule->ops); free(rule->raw_text);
                    return -1;
                }
                t.pattern.bytes = hbytes;
                t.pattern.mask = hmask;
                t.pattern.len = hlen;
                t.pattern.nocase = 0;
                t.pattern.has_wildcard = 0;
                for (size_t i = 0; i < hlen; i++) {
                    if (hmask[i] == 0) { t.pattern.has_wildcard = 1; break; }
                }
            } else {
                fprintf(stderr, "malscan: parse error in %s:%d - expected string or hex pattern near '%.20s'\n",
                        filepath, lineno, p);
                free(rule->terms); free(rule->ops); free(rule->raw_text);
                return -1;
            }

            if (rule->term_count >= cap) {
                cap *= 2;
                rule->terms = (Term *)realloc(rule->terms, sizeof(Term) * cap);
                rule->ops = (BoolOp *)realloc(rule->ops, sizeof(BoolOp) * cap);
            }
            rule->terms[rule->term_count++] = t;
            expect_term = 0;
        } else {
            skip_spaces(&p);
            if (match_keyword(&p, "and")) {
                rule->ops[rule->term_count - 1] = OP_AND;
                expect_term = 1;
            } else if (match_keyword(&p, "or")) {
                rule->ops[rule->term_count - 1] = OP_OR;
                expect_term = 1;
            } else if (*p == '\0') {
                break;
            } else {
                fprintf(stderr, "malscan: parse error in %s:%d - expected 'and'/'or' near '%.20s'\n",
                        filepath, lineno, p);
                for (int i = 0; i < rule->term_count; i++) pattern_free(&rule->terms[i].pattern);
                free(rule->terms); free(rule->ops); free(rule->raw_text);
                return -1;
            }
        }
    }

    if (rule->term_count == 0 || expect_term) {
        fprintf(stderr, "malscan: parse error in %s:%d - incomplete rule expression\n",
                filepath, lineno);
        for (int i = 0; i < rule->term_count; i++) pattern_free(&rule->terms[i].pattern);
        free(rule->terms); free(rule->ops); free(rule->raw_text);
        return -1;
    }

    return 0;
}

static int eval_term(const Term *t, const unsigned char *hay, size_t hlen) {
    int found = pattern_matches(hay, hlen, &t->pattern);
    return t->negate ? !found : found;
}

int eval_rule(const Rule *rule, const unsigned char *hay, size_t hlen) {
    int or_acc = 0;
    int and_acc = eval_term(&rule->terms[0], hay, hlen);

    for (int i = 0; i < rule->term_count - 1; i++) {
        int next_val = eval_term(&rule->terms[i + 1], hay, hlen);
        if (rule->ops[i] == OP_AND) {
            and_acc = and_acc && next_val;
        } else { /* OP_OR */
            or_acc = or_acc || and_acc;
            and_acc = next_val;
        }
    }
    or_acc = or_acc || and_acc;
    return or_acc;
}
