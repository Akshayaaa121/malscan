#include "platform.h"
#include "bytebuf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int read_file_bytes(const char *path, ByteBuf *out) {
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

void bytebuf_free(ByteBuf *b) {
    free(b->data);
    b->data = NULL;
    b->len = 0;
}

char *read_file_text(const char *path) {
    ByteBuf b;
    if (read_file_bytes(path, &b) != 0) return NULL;
    char *s = (char *)malloc(b.len + 1);
    if (!s) { bytebuf_free(&b); return NULL; }
    memcpy(s, b.data, b.len);
    s[b.len] = '\0';
    bytebuf_free(&b);
    return s;
}
