
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

    ByteBuf target;
    if (read_file_bytes(target_path, &target) != 0) {
        fprintf(stderr, "malscan: error: cannot read target file '%s'\n", target_path);
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
