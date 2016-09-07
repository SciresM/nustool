#ifndef NUSTOOL_DOWNLOAD_H
#define NUSTOOL_DOWNLOAD_H

#include <stdio.h>

#include "crypto.h"
#include "types.h"

#define NUS_BASE_URL		"http://ccs.cdn.c.shop.nintendowifi.net/ccs/download/"
/* "http://nus.cdn.c.shop.nintendowifi.net/ccs/download/" */
#define NUS_BASE_URL_LEN	52
/* "http://nus.cdn.c.shop.nintendowifi.net/ccs/download/0000000000000000/" */
#define NUS_TITLE_BASE_URL_LEN	69
/* "http://nus.cdn.c.shop.nintendowifi.net/ccs/download/0000000000000000/tmd" */
#define NUS_TMD_NOVER_URL_LEN	72

errno_t download_title(void);

#define DS_ERROR	(1UL << 31)

#define TYPE_ENCRYPTED		(1U <<  0)
/* aka type "disc" */
#define TYPE_BLOCKWISECRYPTO	(1U <<  1)
#define TYPE_CFM		(1U <<  2)
/* Flag 0x2000 unknown. */
#define TYPE_OPTIONAL		(1U << 14)
#define TYPE_SHARED		(1U << 15)

#define CHUNK_SIZE		0x10000U
#define BLOCK_SIZE		0x0fc00U
#define CHUNK_HEADER_SIZE	0x00400U
#define HN_SIZE			0x140U

/* TMD content */
struct Content {
	struct Content *next;

	uint32_t contentid;
	/* We only use this for the IV for decryption anyway, so there's no
	 * use storing this as a uint16_t.
	 */
	byte idx[2];
	uint16_t type;
	uint64_t size;
	int hashalgo;
	/* Holds a SHA-1 hash with 0-padding.
	 * On 3DS, holds a SHA-256 hash.
	 */
	byte hash[0x20];
	/* Used for blockwise crypto: Top level hash of this hash tree. */
	byte h3[0x20];
};

struct HnCounters {
	size_t h0;
	size_t h1;
	size_t h2;
};

struct DownloadState {
	unsigned long flags;
	struct Content *content;
	FILE *f;

	size_t bytes_hashed;
	struct HnCounters count;
	gcry_cipher_hd_t cipher;
	gcry_md_hd_t hasher;
};

struct DownloadCryptoContext {
	unsigned char *data;
	size_t datalen;
	struct DownloadState *ds;
};

enum SignatureTypeID {
	SIG_UNDERFLOW		= 0x00FFFF,
	RSA_4096_SHA_1		= 0x010000,
	RSA_2048_SHA_1		= 0x010001,
	EC_SHA_1		= 0x010002,
	RSA_4096_SHA_256	= 0x010003,
	RSA_2048_SHA_256	= 0x010004,
	EC_SHA_256		= 0x010005,
	SIG_OVERFLOW		= 0x010006
};

struct TMDFileFormat {
	size_t ncontents_offset;
	size_t contents_offset;
	size_t content_chunk_len;
	size_t hash_len;
};

static inline bool has_simple_crypto(const struct Content *content)
{
	return ((content->type & TYPE_ENCRYPTED)
		&& !(content->type & TYPE_BLOCKWISECRYPTO));
}

#endif

