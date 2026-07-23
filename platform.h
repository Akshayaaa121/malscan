/*
 * platform.h
 * ---------------------------------------------------------------------------
 * Feature-test macros needed so glibc's headers expose POSIX/BSD
 * extensions (strdup, strtok_r, strcasecmp, lstat) even under a strict
 * -std=c11 build. Without these, those functions get implicitly
 * declared as returning `int`, which silently truncates pointers on
 * 64-bit platforms and crashes at runtime.
 *
 * IMPORTANT: this header must be the very first #include in any .c
 * file that (directly or indirectly, via another project header) ends
 * up including a system header like <string.h>, <dirent.h>, or
 * <sys/stat.h>. Feature-test macros only take effect if defined
 * before the relevant system header is first pulled in.
 * ---------------------------------------------------------------------------
 */
#ifndef MALSCAN_PLATFORM_H
#define MALSCAN_PLATFORM_H

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#endif /* MALSCAN_PLATFORM_H */
