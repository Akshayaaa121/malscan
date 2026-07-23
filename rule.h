
#ifndef MALSCAN_RULE_H
#define MALSCAN_RULE_H

#include <stddef.h>
#include "pattern.h"

typedef struct {
    Pattern pattern;
    int negate;
} Term;

typedef enum { OP_AND, OP_OR } BoolOp;

typedef struct {
    Term *terms;
    int term_count;
    BoolOp *ops;    
    char *raw_text; 
} Rule;


void rule_free(Rule *r);


int parse_rule_line(const char *line, Rule *rule, const char *filepath, int lineno);


 * bytes hay[0..hlen). Returns 1 if the rule matches, 0 otherwise. */
int eval_rule(const Rule *rule, const unsigned char *hay, size_t hlen);

#endif 
