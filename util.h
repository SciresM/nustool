#ifndef NUSTOOL_UTIL_H
#define NUSTOOL_UTIL_H

#include "types.h"

#define MAX_FILEPATH_LEN (16+1+6+1+9)
#define MAX_FILENAME_LEN (9)

void oom(void) __attribute__((noreturn));
void err(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void msg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
errno_t util_parse_hex(char *in, byte *out, size_t outlen);
errno_t util_create_outdir(void);
char *util_get_filepath(const char *path);
const char *util_print_hex(const byte bytes[], size_t length, char *out);
errno_t util_parse_options(int argc, char *argv[]);
errno_t util_create_file(const char *path);
errno_t util_get_file_size(const char *path, uint64_t *size);
uint8_t util_get_msb64(uint64_t i);
char *util_realloc_and_append_fmt(char *base, size_t appendlen, const char *fmt,
		...) __attribute__((format(printf, 3, 4)));

#endif

