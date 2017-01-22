#ifndef NUSTOOL_MAIN_H
#define NUSTOOL_MAIN_H

#include "types.h"

#define OPT_SHOW_PROGRESS	(1UL << 0)
#define OPT_HAS_KEY		(1UL << 1)
#define OPT_HAS_VERSION		(1UL << 2)
#define OPT_DECRYPT_FROM_CETK	(1UL << 3)
#define OPT_KEY_ENCRYPTED	(1UL << 4)
#define OPT_KEEP_META		(1UL << 5)
#define OPT_RESUME		(1UL << 6)
#define OPT_DEV_KEYS		(1UL << 7)
#define OPT_LOCAL_FILES		(1UL << 8)

struct Options {
	uint64_t titleid;
	byte key[16];
	unsigned long flags;
	uint16_t version;
};

extern struct Options opts;

#endif

