/*
 * main.c
 * ---------------------------------------------------------------------------
 * A rules-based malware detection engine.
 *
 *   ./malscan <file_to_scan> <rules_directory>
 *
 * See README.md for the full rule-file format and design notes. In short:
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
 * Each malware family is one file, split into [metadata] and [rules].
 * A rule (one line) is a boolean expression over string/hex terms.
 * A family matches if ANY of its rules match. The rules directory may
 * be nested arbitrarily deep; every regular file underneath is
 * considered a candidate rule file (non-rule files are skipped).
 * The scanned target file is always treated as an opaque byte blob --
 * no assumption is made about its encoding or structure.
 * ---------------------------------------------------------------------------
 */
#include "platform.h"

#include <stdio.h>
#include <stdlib.h>

#include "bytebuf.h"
#include "malwaredef.h"
#include "dirwalk.h"
#include "rule.h"

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

    /* --- Load target file (arbitrary bytes, no encoding assumptions) --- */
    ByteBuf target;
    if (read_file_bytes(target_path, &target) != 0) {
        fprintf(stderr, "malscan: error: cannot read target file '%s'\n", target_path);
        return 2;
    }

    /* --- Collect all candidate rule files (recursive) --- */
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
            /* Not a rule file (no [metadata]/[rules] markers) -- skip it. */
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
