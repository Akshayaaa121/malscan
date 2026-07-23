/*
 * malscan.c
 * ---------------------------------------------------------------------------
 * A rules-based malware detection engine.
 *
 * USAGE:
 *   ./malscan <file_to_scan> <rules_directory>
 *
 * DESIGN SUMMARY
 * ---------------------------------------------------------------------------
 * Rule file format (one file per malware family, arbitrary extension,
 * arbitrarily nested inside the rules directory):
 *
 *   [metadata]
 *   name = TrojanX
 *   description = Injects into remote processes and phones home
 *
 *   [rules]
 *   "CreateRemoteThread" and "VirtualAllocEx"
 *   {4D 5A 90 00 03 00 00 00} and "kernel32.dll" nocase
 *   "powershell -enc" or "cmd.exe /c" or {68 74 74 70 3A 2F 2F}
 *   not "SAFE_MARKER_1234" and "evil_payload"
 *
 * - Section 1 ([metadata]) names/describes the malware family.
 * - Section 2 ([rules]) holds the actual detection logic, ONE RULE PER LINE.
 * - A rule is a boolean expression over one or more "terms".
 * - A term is either:
 *      "quoted string"          -> literal byte sequence (escapes allowed)
 *      "quoted string" nocase   -> case-insensitive literal byte sequence
 *      { AA BB ?? CC }          -> raw hex byte pattern; ?? = wildcard byte
 * - Terms are combined with the boolean keywords: not, and, or
 *   (standard precedence: NOT binds tightest, then AND, then OR;
 *    no parentheses in this version -- documented simplification).
 * - A RULE matches the scanned file if its boolean expression evaluates
 *   true against that file's raw bytes.
 * - A MALWARE FAMILY (rule file) matches if ANY of its rules match
 *   (rules within one file are OR'd together at the file level).
 * - The scanned file matches "malware" overall if ANY family's file matches.
 *
 * The target file is always treated as an opaque byte blob -- no assumption
 * is made about text encoding, executable format, etc. All searching is
 * done with memory-safe, NUL-byte-tolerant routines (never strstr/strlen on
 * file content).
 *
 * MATCHING ALGORITHMS
 * ---------------------------------------------------------------------------
 * - Exact byte patterns (no wildcard, case-sensitive): Boyer-Moore-Horspool,
 *   which gives good sub-linear average-case performance on large binaries.
 * - Patterns with wildcards or nocase: a straightforward skip-search that
 *   checks match at every candidate offset (still linear-ish in practice
 *   because these patterns are typically short).
 *
 * Build:  gcc -O2 -Wall -Wextra -o malscan malscan.c
 * ---------------------------------------------------------------------------
 */

/* Feature-test macros: needed so glibc's headers expose POSIX/BSD
 * extensions (strdup, strtok_r, strcasecmp, lstat) even when compiling
 * with a strict -std=c11 (which otherwise hides them, causing them to
 * be implicitly declared as returning int -- silently truncating
 * pointers on 64-bit platforms and crashing at runtime). Must be
 * defined before any system header is included. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>

/* ============================================================
 * Dynamic string / byte-buffer helpers
 * ============================================================ */

typedef struct {
    unsigned char *data;
    size_t len;
} ByteBuf;

static void bytebuf_free(ByteBuf *b) {
    free(b->data);
    b->data = NULL;
    b->len = 0;
}

/* Read an entire file into memory as raw bytes (binary-safe). */
static int read_file_bytes(const char *path, ByteBuf *out) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long size = ftell(f);
    if (size < 0) { fclose(f); return -1; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }

    unsigned char *buf = (unsigned char *)malloc((size_t)size > 0 ? (size_t)size : 1);
    if (!buf) { fclose(f); return -1; }

    size_t read_total = 0;
    if (size > 0) {
        read_total = fread(buf, 1, (size_t)size, f);
    }
    fclose(f);

    if ((long)read_total != size) {
        free(buf);
        return -1;
    }

    out->data = buf;
    out->len = (size_t)size;
    return 0;
}

/* Read an entire file into memory as a NUL-terminated text blob
 * (used only for rule files, which we treat as text for parsing). */
static char *read_file_text(const char *path) {
    ByteBuf b;
    if (read_file_bytes(path, &b) != 0) return NULL;
    char *s = (char *)malloc(b.len + 1);
    if (!s) { bytebuf_free(&b); return NULL; }
    memcpy(s, b.data, b.len);
    s[b.len] = '\0';
    bytebuf_free(&b);
    return s;
}

/* ============================================================
 * Pattern representation
 * ============================================================
 * A pattern is a sequence of bytes plus a parallel "mask" array.
 * mask[i] == 1 means "this byte must match exactly (respecting nocase)".
 * mask[i] == 0 means "wildcard: any byte matches here".
 */

typedef struct {
    unsigned char *bytes;
    unsigned char *mask;
    size_t len;
    int nocase;      /* 1 if this is a case-insensitive string pattern */
    int has_wildcard;/* 1 if any mask[i] == 0 */
} Pattern;

static void pattern_free(Pattern *p) {
    free(p->bytes);
    free(p->mask);
    p->bytes = NULL;
    p->mask = NULL;
    p->len = 0;
}

/* ============================================================
 * Term / Rule / MalwareDef data structures
 * ============================================================ */

typedef struct {
    Pattern pattern;
    int negate; /* 1 if preceded by "not" */
} Term;

typedef enum { OP_AND, OP_OR } BoolOp;

typedef struct {
    Term *terms;
    int term_count;
    BoolOp *ops;      /* term_count - 1 operators, ops[i] joins terms[i] and terms[i+1] */
    char *raw_text;   /* original rule line text, for reporting */
} Rule;

typedef struct {
    char name[256];
    char description[1024];
    Rule *rules;
    int rule_count;
    int rule_capacity;
    char filepath[4096];
} MalwareDef;

static void rule_free(Rule *r) {
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

static void malwaredef_free(MalwareDef *m) {
    for (int i = 0; i < m->rule_count; i++) {
        rule_free(&m->rules[i]);
    }
    free(m->rules);
    m->rules = NULL;
    m->rule_count = 0;
    m->rule_capacity = 0;
}

/* ============================================================
 * Rule-line tokenizer / parser
 * ============================================================
 * Grammar (per line, i.e. per rule):
 *
 *   rule       := andExpr (OR andExpr)*
 *   andExpr    := notTerm (AND notTerm)*
 *   notTerm    := [NOT] term
 *   term       := stringLit [NOCASE] | hexLit
 *
 * We parse this into a flat terms[] array with a parallel ops[] array
 * (all AND/OR at the same "level"), because we evaluate AND before OR
 * in a single pass later (see eval_rule()). This flattening works because
 * there's no parenthesization to worry about.
 */

/* Parse a quoted string literal starting at *p (which points at the
 * opening '"'). Handles escapes: \" \\ \n \t \r \xHH.
 * Advances *p past the closing quote. Returns malloc'd raw bytes
 * (not NUL-terminated logically, but a NUL terminator is appended for
 * safety) and sets *out_len. Returns NULL on malformed input. */
static unsigned char *parse_quoted_string(const char **p, size_t *out_len) {
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
                        lo = 0; /* mark valid */
                        s += 2;
                    }
                    if (lo == -1) {
                        /* malformed \x escape; treat literally */
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
    s++; /* skip closing quote */

    *p = s;
    *out_len = n;
    return buf;
}

/* Parse a hex byte pattern starting at *p (pointing at '{').
 * Bytes are two hex digits separated by whitespace; "??" is a wildcard
 * byte. Fills bytes[]/mask[] arrays (both malloc'd) and out_len.
 * Advances *p past the closing '}'. Returns 0 on success, -1 on error. */
static int parse_hex_pattern(const char **p, unsigned char **out_bytes,
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
            mask[n] = 0; /* wildcard */
            n++;
            s += 2;
        } else if (isxdigit((unsigned char)s[0]) && isxdigit((unsigned char)s[1])) {
            char tmp[3] = { s[0], s[1], '\0' };
            bytes[n] = (unsigned char)strtol(tmp, NULL, 16);
            mask[n] = 1;
            n++;
            s += 2;
        } else {
            /* invalid character inside hex pattern */
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

static void skip_spaces(const char **p) {
    while (isspace((unsigned char)**p)) (*p)++;
}

/* Case-insensitive keyword match at *p; if matched, advances *p past it
 * (and past any following whitespace) and returns 1. Otherwise returns 0
 * and leaves *p unchanged. Requires a word boundary after the keyword. */
static int match_keyword(const char **p, const char *kw) {
    const char *s = *p;
    size_t klen = strlen(kw);
    for (size_t i = 0; i < klen; i++) {
        if (tolower((unsigned char)s[i]) != tolower((unsigned char)kw[i])) return 0;
    }
    /* word boundary check */
    char after = s[klen];
    if (isalnum((unsigned char)after) || after == '_') return 0;

    *p = s + klen;
    skip_spaces(p);
    return 1;
}

/* Parses one full rule line into a Rule struct.
 * Returns 0 on success, -1 on parse error (message printed to stderr). */
static int parse_rule_line(const char *line, Rule *rule, const char *filepath, int lineno) {
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
            /* handle one or more leading "not" */
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
            /* expect an operator */
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

/* ============================================================
 * Pattern searching engines
 * ============================================================ */

/* Boyer-Moore-Horspool for exact (no wildcard, case-sensitive) patterns.
 * Returns 1 if pat is found anywhere in hay, else 0. */
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

/* Generic matcher for patterns that have wildcards and/or are
 * case-insensitive. Checks every candidate offset directly. */
static int generic_search(const unsigned char *hay, size_t hlen, const Pattern *pat) {
    size_t plen = pat->len;
    if (plen == 0) return 1;
    if (plen > hlen) return 0;

    for (size_t pos = 0; pos <= hlen - plen; pos++) {
        int ok = 1;
        for (size_t j = 0; j < plen; j++) {
            if (pat->mask[j] == 0) continue; /* wildcard, always matches */
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

/* Dispatches to the fastest applicable search strategy. */
static int pattern_matches(const unsigned char *hay, size_t hlen, const Pattern *pat) {
    if (pat->has_wildcard || pat->nocase) {
        return generic_search(hay, hlen, pat);
    }
    return bmh_search(hay, hlen, pat->bytes, pat->len);
}

/* ============================================================
 * Rule evaluation: AND binds tighter than OR, left to right,
 * no parentheses (flattened single-pass evaluation).
 * ============================================================ */

static int eval_term(const Term *t, const unsigned char *hay, size_t hlen) {
    int found = pattern_matches(hay, hlen, &t->pattern);
    return t->negate ? !found : found;
}

/* Evaluates the flattened terms[]/ops[] expression with AND-before-OR
 * precedence: we scan left to right, accumulating an AND-chain into
 * `and_acc`; whenever we hit an OR (or the end), we OR that chain's
 * result into `or_acc` and start a new AND-chain. */
static int eval_rule(const Rule *rule, const unsigned char *hay, size_t hlen) {
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

/* ============================================================
 * Rule FILE parsing: [metadata] + [rules] sections
 * ============================================================ */

static char *trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

static int parse_rule_file(const char *filepath, const char *text, MalwareDef *def) {
    memset(def, 0, sizeof(*def));
    strncpy(def->filepath, filepath, sizeof(def->filepath) - 1);
    strcpy(def->name, "(unnamed)");
    def->description[0] = '\0';

    def->rule_capacity = 8;
    def->rules = (Rule *)malloc(sizeof(Rule) * def->rule_capacity);
    def->rule_count = 0;

    enum { SEC_NONE, SEC_METADATA, SEC_RULES } section = SEC_NONE;
    int saw_metadata = 0, saw_rules = 0;

    char *buf = strdup(text);
    char *saveptr = NULL;
    char *line = strtok_r(buf, "\n", &saveptr);
    int lineno = 0;

    while (line != NULL) {
        lineno++;
        size_t L = strlen(line);
        if (L > 0 && line[L - 1] == '\r') line[L - 1] = '\0';

        char *trimmed = trim(line);

        if (trimmed[0] == '\0' || trimmed[0] == '#') {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        if (strcasecmp(trimmed, "[metadata]") == 0) {
            section = SEC_METADATA;
            saw_metadata = 1;
        } else if (strcasecmp(trimmed, "[rules]") == 0) {
            section = SEC_RULES;
            saw_rules = 1;
        } else if (section == SEC_METADATA) {
            char *eq = strchr(trimmed, '=');
            if (eq) {
                *eq = '\0';
                char *key = trim(trimmed);
                char *val = trim(eq + 1);
                if (strcasecmp(key, "name") == 0) {
                    strncpy(def->name, val, sizeof(def->name) - 1);
                } else if (strcasecmp(key, "description") == 0) {
                    strncpy(def->description, val, sizeof(def->description) - 1);
                }
            }
        } else if (section == SEC_RULES) {
            Rule r;
            if (parse_rule_line(trimmed, &r, filepath, lineno) == 0) {
                if (def->rule_count >= def->rule_capacity) {
                    def->rule_capacity *= 2;
                    def->rules = (Rule *)realloc(def->rules, sizeof(Rule) * def->rule_capacity);
                }
                def->rules[def->rule_count++] = r;
            }
        }

        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(buf);

    if (!saw_metadata && !saw_rules) {
        /* Not a rule file at all -- release the rules array we
         * speculatively allocated up front (rule_count is 0 here,
         * since the only way to add rules is via a [rules] section,
         * and seeing one would have set saw_rules). */
        free(def->rules);
        def->rules = NULL;
        def->rule_count = 0;
        def->rule_capacity = 0;
        return -1;
    }
    return 0;
}

/* ============================================================
 * Recursive directory walk to collect candidate rule file paths
 * ============================================================ */

typedef struct {
    char **paths;
    int count;
    int capacity;
} PathList;

static void pathlist_init(PathList *pl) {
    pl->capacity = 16;
    pl->count = 0;
    pl->paths = (char **)malloc(sizeof(char *) * pl->capacity);
}

static void pathlist_add(PathList *pl, const char *path) {
    if (pl->count >= pl->capacity) {
        pl->capacity *= 2;
        pl->paths = (char **)realloc(pl->paths, sizeof(char *) * pl->capacity);
    }
    pl->paths[pl->count++] = strdup(path);
}

static void pathlist_free(PathList *pl) {
    for (int i = 0; i < pl->count; i++) free(pl->paths[i]);
    free(pl->paths);
    pl->paths = NULL;
    pl->count = pl->capacity = 0;
}

static void walk_dir(const char *dir, PathList *out) {
    DIR *d = opendir(dir);
    if (!d) {
        fprintf(stderr, "malscan: warning: cannot open directory '%s': %s\n",
                dir, strerror(errno));
        return;
    }

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;

        char path[4096];
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);

        struct stat st;
        if (lstat(path, &st) != 0) continue;

        if (S_ISLNK(st.st_mode)) {
            continue;
        } else if (S_ISDIR(st.st_mode)) {
            walk_dir(path, out);
        } else if (S_ISREG(st.st_mode)) {
            pathlist_add(out, path);
        }
    }
    closedir(d);
}

/* ============================================================
 * Main
 * ============================================================ */

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <file_to_scan> <rules_directory>\n\n"
        "  <file_to_scan>      Any file: binary, text, unicode, etc.\n"
        "  <rules_directory>   Directory containing malware rule files.\n"
        "                      May be arbitrarily nested; every regular\n"
        "                      file inside is checked as a candidate rule\n"
        "                      file.\n", prog);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        print_usage(argv[0]);
        return 2;
    }

    const char *target_path = argv[1];
    const char *rules_dir = argv[2];

    ByteBuf target;
    if (read_file_bytes(target_path, &target) != 0) {
        fprintf(stderr, "malscan: error: cannot read target file '%s': %s\n",
                target_path, strerror(errno));
        return 2;
    }

    PathList paths;
    pathlist_init(&paths);
    walk_dir(rules_dir, &paths);

    if (paths.count == 0) {
        fprintf(stderr, "malscan: warning: no files found under rules directory '%s'\n", rules_dir);
    }

    int total_families = 0;
    int matched_families = 0;

    printf("Scanning: %s (%zu bytes)\n", target_path, target.len);
    printf("Rules directory: %s (%d candidate file(s) found)\n\n", rules_dir, paths.count);

    for (int i = 0; i < paths.count; i++) {
        char *text = read_file_text(paths.paths[i]);
        if (!text) {
            fprintf(stderr, "malscan: warning: cannot read rule file '%s'\n", paths.paths[i]);
            continue;
        }

        MalwareDef def;
        int rc = parse_rule_file(paths.paths[i], text, &def);
        free(text);

        if (rc != 0) {
            continue;
        }

        total_families++;

        int family_matched = 0;
        int *matched_rule_idx = (int *)malloc(sizeof(int) * (def.rule_count > 0 ? def.rule_count : 1));
        int matched_count = 0;

        for (int r = 0; r < def.rule_count; r++) {
            if (eval_rule(&def.rules[r], target.data, target.len)) {
                family_matched = 1;
                matched_rule_idx[matched_count++] = r;
            }
        }

        if (family_matched) {
            matched_families++;
            printf("[MATCH] %s\n", def.name);
            if (def.description[0]) {
                printf("        Description: %s\n", def.description);
            }
            printf("        Definition file: %s\n", def.filepath);
            for (int k = 0; k < matched_count; k++) {
                printf("        Matched rule: %s\n", def.rules[matched_rule_idx[k]].raw_text);
            }
            printf("\n");
        }

        free(matched_rule_idx);
        malwaredef_free(&def);
    }

    printf("---------------------------------------------\n");
    printf("Families evaluated: %d\n", total_families);
    printf("Families matched:   %d\n", matched_families);

    pathlist_free(&paths);
    bytebuf_free(&target);

    return matched_families > 0 ? 1 : 0;
}
