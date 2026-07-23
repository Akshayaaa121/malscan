
#ifndef MALSCAN_BYTEBUF_H
#define MALSCAN_BYTEBUF_H

#include <stddef.h>

typedef struct {
    unsigned char *data;
    size_t len;
} ByteBuf;


int read_file_bytes(const char *path, ByteBuf *out);


void bytebuf_free(ByteBuf *b);


char *read_file_text(const char *path);

#endif 
