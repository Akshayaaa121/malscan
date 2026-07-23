/*
 * bytebuf.h
 * ---------------------------------------------------------------------------
 * A minimal binary-safe byte buffer, used to hold the target file being
 * scanned. Never treated as a NUL-terminated C string -- the scanned
 * file may be any format (executable, text, Unicode, etc.) and must
 * not have any encoding or structure assumed about it.
 * ---------------------------------------------------------------------------
 */
#ifndef MALSCAN_BYTEBUF_H
#define MALSCAN_BYTEBUF_H

#include <stddef.h>

typedef struct {
    unsigned char *data;
    size_t len;
} ByteBuf;

/* Reads the entire file at `path` into a freshly malloc'd buffer.
 * Returns 0 on success (fills *out), -1 on failure (check errno). */
int read_file_bytes(const char *path, ByteBuf *out);

/* Releases the buffer owned by `b` and zeroes it out. */
void bytebuf_free(ByteBuf *b);

/* Reads the entire file at `path` as a NUL-terminated text blob. Used
 * only for rule files (which we treat as text for parsing purposes),
 * never for the arbitrary-format scan target. Caller must free() the
 * returned pointer. Returns NULL on failure. */
char *read_file_text(const char *path);

#endif /* MALSCAN_BYTEBUF_H */
