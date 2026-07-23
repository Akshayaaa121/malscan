#include "platform.h"
#include "dirwalk.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>

void pathlist_init(PathList *pl) {
    pl->capacity = 16;
    pl->count = 0;
    pl->paths = (char **)malloc(sizeof(char *) * pl->capacity);
}

void pathlist_add(PathList *pl, const char *path) {
    if (pl->count >= pl->capacity) {
        pl->capacity *= 2;
        pl->paths = (char **)realloc(pl->paths, sizeof(char *) * pl->capacity);
    }
    pl->paths[pl->count++] = strdup(path);
}

void pathlist_free(PathList *pl) {
    for (int i = 0; i < pl->count; i++) free(pl->paths[i]);
    free(pl->paths);
    pl->paths = NULL;
    pl->count = pl->capacity = 0;
}

void walk_dir(const char *dir, PathList *out) {
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
            continue; /* don't follow symlinks: avoids cycles */
        } else if (S_ISDIR(st.st_mode)) {
            walk_dir(path, out); /* recurse into subfolder */
        } else if (S_ISREG(st.st_mode)) {
            pathlist_add(out, path);
        }
    }
    closedir(d);
}
