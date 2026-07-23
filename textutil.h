
#ifndef MALSCAN_TEXTUTIL_H
#define MALSCAN_TEXTUTIL_H

void skip_spaces(const char **p);

int match_keyword(const char **p, const char *kw);


char *trim(char *s);

#endif 
