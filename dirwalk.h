/*
 * dirwalk.h
 * ---------------------------------------------------------------------------
 * Recursively collects every regular file's path under a given
 * directory into a growable PathList. Used to discover rule files
 * inside an arbitrarily nested rules directory tree. Symlinks are not
 * followed, to avoid infinite loops on cyclic symlink trees.
 * ---------------------------------------------------------------------------
 */
#ifndef MALSCAN_DIRWALK_H
#define MALSCAN_DIRWALK_H

typedef struct {
    char **paths;
    int count;
    int capacity;
} PathList;

void pathlist_init(PathList *pl);
void pathlist_add(PathList *pl, const char *path);
void pathlist_free(PathList *pl);

/* Recursively walks `dir`, appending every regular file's full path to
 * `out`. Directories are recursed into at any depth; "." and ".." are
 * skipped; symlinks are skipped entirely (not followed). */
void walk_dir(const char *dir, PathList *out);

#endif /* MALSCAN_DIRWALK_H */
