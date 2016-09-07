#ifndef NUSTOOL_UTIL_H
#define NUSTOOL_UTIL_H

#include "types.h"

void oom(void) __attribute__((noreturn));
void err(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void msg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
errno_t util_parse_hex(char *in, byte *out, size_t outlen);
const char *util_print_hex(const byte bytes[], size_t length, char *out);
errno_t util_parse_options(int argc, char *argv[]);
errno_t util_get_file_size(const char *path, uint64_t *size);

#endif

