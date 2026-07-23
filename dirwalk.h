
 
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

void walk_dir(const char *dir, PathList *out);

#endif 
