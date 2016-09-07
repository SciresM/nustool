#ifdef __WIN32
 #define CURL_STATICLIB
#endif

#include <curl/curl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "crypto.h"
#include "main.h"
#include "download.h"
#include "types.h"
#include "util.h"

#ifdef __linux__ 
    #define CURL_INIT_VARS CURL_GLOBAL_NOTHING
#elif _WIN32
    #define CURL_INIT_VARS CURL_GLOBAL_WIN32
#endif

static CURL *curl;
static char errbuf[CURL_ERROR_SIZE];
/* "http://nus.cdn.c.shop.nintendowifi.net/ccs/download/0000000000000000/00000000.h3" + '\0' */
static char urlbuf[81];

static byte *tmd = NULL;
static size_t tmdsize;
static byte *cetk = NULL;
static size_t cetksize;
static struct Content *contents = NULL;

static const char *curlerrstr(CURLcode code)
{
	if (*errbuf)
		return errbuf;
	else
		return curl_easy_strerror(code);
}

static char *get_base_url_for_titleid(uint64_t titleid)
{
	strcpy(urlbuf, NUS_BASE_URL);

	snprintf(urlbuf + NUS_BASE_URL_LEN, sizeof(urlbuf) - NUS_BASE_URL_LEN,
			"%016" PRIx64 "/", titleid);

	return urlbuf;
}

static const char *get_tmd_url(void)
{
	strcat(get_base_url_for_titleid(opts.titleid), "tmd");

	if (!(opts.flags & OPT_HAS_VERSION))
		return urlbuf;

	snprintf(urlbuf + NUS_TMD_NOVER_URL_LEN,
			sizeof(urlbuf) - NUS_TMD_NOVER_URL_LEN,
			".%" PRIu16, opts.version);

	return urlbuf;
}

static const char *get_cetk_url(void)
{
	strcat(get_base_url_for_titleid(opts.titleid), "cetk");

	return urlbuf;
}

static const char *get_content_url(const struct Content *content)
{
	(void)get_base_url_for_titleid(opts.titleid);

	snprintf(urlbuf + NUS_TITLE_BASE_URL_LEN,
			sizeof(urlbuf) - NUS_TITLE_BASE_URL_LEN,
			"%08" PRIx32, content->contentid);

	return urlbuf;
}

static const char *get_h3_url_for_content(const struct Content *content)
{
	(void)get_base_url_for_titleid(opts.titleid);

	snprintf(urlbuf + NUS_TITLE_BASE_URL_LEN,
			sizeof(urlbuf) - NUS_TITLE_BASE_URL_LEN,
			"%08" PRIx32 ".h3", content->contentid);

	return urlbuf;
}


static errno_t download_init(void)
{
	CURLcode code;

	/* Forward-compatibility: CURL_GLOBAL_SSL needs setting if Nintendo ever
	 * switches to a TLS/SSL CDN.
	 */
	if ((code = curl_global_init(CURL_INIT_VARS)) != CURLE_OK) {
		err("curl_global_init: %s", curl_easy_strerror(code));
		return -1;
	}

	if ((curl = curl_easy_init()) == NULL)
		return -1;

	if ((code = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf))
			!= CURLE_OK) {
		err("curl_easy_setopt(ERRORBUFFER): %s",
				curlerrstr(code));
		return -1;
	}

	if ((code = curl_easy_setopt(curl, CURLOPT_NOPROGRESS,
			!(opts.flags & OPT_SHOW_PROGRESS))) != CURLE_OK) {
		err("curl_easy_setopt(NOPROGRESS): %s",
				curlerrstr(code));
		return -1;
	}

	if ((code = curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1))
			!= CURLE_OK) {
		err("curl_easy_setopt(FAILONERROR): %s",
				curlerrstr(code));
		return -1;
	}

	if ((code = curl_easy_setopt(curl, CURLOPT_USERAGENT,
					"CTR/P/1.0.0/r61631"))
			!= CURLE_OK) {
		err("curl_easy_setopt(USERAGENT): %s",
				curlerrstr(code));
		return -1;
	}

	return 0;
}

static struct Content *make_content(void)
{
	struct Content *content;

	if ((content = malloc(sizeof(*content))) == NULL)
		oom();

	content->next = contents;
	contents = content;

	return content;
}

static inline bool is_valid_sig_type(uint32_t type)
{
	return (type == 0
			|| (type > SIG_UNDERFLOW && type < SIG_OVERFLOW));
}

static inline ssize_t bytes_to_skip_for_signature(uint32_t sigtype)
{
	enum SignatureTypeID type;

	if (!is_valid_sig_type(sigtype))
		return -1;

	/* This seems to happen with some Ambassador tickets. */
	if (sigtype == 0)
		type = RSA_2048_SHA_256;
	else
		type = (enum SignatureTypeID)sigtype;

	switch (type) {
	/* Unused. */
	case RSA_4096_SHA_1:
	case RSA_4096_SHA_256:
		return 0x23c;

	/* Wii, DSi, maybe Wii U */
	case RSA_2048_SHA_1:
	/* 3DS */
	case RSA_2048_SHA_256:
		return 0x13c;

	/* Unused. */
	case EC_SHA_1:
	case EC_SHA_256:
		return 0x7c;

	case SIG_UNDERFLOW:
	case SIG_OVERFLOW:
		return -1;
	}

	return -1;
}

/* Indexed by TMD version. */
static struct TMDFileFormat tmd_format[] = {
	/* TMD version = 0 (Wii, DSi) */
	{
		.ncontents_offset = 0x9e,
		.contents_offset = 0xa4,
		.content_chunk_len = 0x24,
		.hash_len = 0x14
	},
	/* TMD version = 1 (3DS, Wii U) */
	{
		.ncontents_offset = 0x9e,
		.contents_offset = 0x9c4,
		.content_chunk_len = 0x30,
		.hash_len = 0x20
	}
};

static errno_t build_contents_list(void)
{
	uint32_t sigtype = ((uint32_t)tmd[0] << 24) | ((uint32_t)tmd[1] << 16)
		| ((uint32_t)tmd[2] << 8) | tmd[3];
	ssize_t offset;
	struct Content *content;
	struct TMDFileFormat *format;
	byte *ptr;
	size_t ncontents;

	if ((offset = bytes_to_skip_for_signature(sigtype)) == -1) {
		err("Error: Unknown signature type %" PRIx32, sigtype);
		return -1;
	}

	/* Account for the initial four bytes used for the signature type. */
	offset += 4;

	if (tmd[offset + 0x40] > 0x1) {
		err("Warning: Unknown TMD version %" PRIu8 ", aborting.",
				tmd[offset + 0x40]);
		return -1;
	}

	format = &tmd_format[tmd[offset + 0x40]];

	ncontents = ((size_t)tmd[(size_t)offset + format->ncontents_offset] << 8)
		| tmd[(size_t)offset + format->ncontents_offset + 1];

	ptr = tmd + offset + format->contents_offset;
	for (size_t i = 0; i < ncontents; ++i) {
		if (ptr + format->content_chunk_len > tmd + tmdsize) {
			err("Attempted to read TMD out of range.");
			return -1;
		}

		if ((content = make_content()) == NULL)
			oom();

		content->contentid = ((uint32_t)ptr[0] << 24) | ((uint32_t)ptr[1] << 16)
			| ((uint32_t)ptr[2] << 8) | ptr[3];
		content->idx[0] = ptr[4];
		content->idx[1] = ptr[5];

		content->type = (uint16_t)(((uint16_t)ptr[6] << 8) | ptr[7]);

		content->size = ((uint64_t)ptr[8] << 56) | 
			((uint64_t)ptr[9] << 48) | 
			((uint64_t)ptr[10] << 40) | 
			((uint64_t)ptr[11] << 32) | 
			((uint64_t)ptr[12] << 24) | 
			((uint64_t)ptr[13] << 16) | 
			((uint64_t)ptr[14] << 8) | 
			ptr[15];

		memcpy(content->hash, ptr + 16, 0x20);

		ptr += format->content_chunk_len;
	}

	return 0;
}

static size_t download_tmd_cb(char *ptr, size_t size, size_t nmemb,
		void *userdata)
{
	struct DownloadState *ds = userdata;
	byte *data = (byte *)ptr;
	size_t datalen = size * nmemb;

	if (nmemb != 0 && datalen / nmemb != size) {
		ds->flags |= DS_ERROR;
		err("Error: Overflow while calculating downloaded size.");
		return 0;
	}

	/* Only happens on empty file */
	if (datalen == 0) {
		ds->flags |= DS_ERROR;
		err("Error: Received 0-length TMD from remote.");
		return 0;
	}

	if (tmd != NULL) {
		if (tmdsize + datalen < tmdsize) {
			ds->flags |= DS_ERROR;
			err("Overflow while calculating downloaded size.");
			return 0;
		}

		if ((tmd = realloc(tmd, tmdsize + datalen)) == NULL)
			oom();

		memcpy(tmd + tmdsize, data, datalen);

		tmdsize += datalen;
	} else {
		if ((tmd = malloc(datalen)) == NULL)
			oom();

		memcpy(tmd, data, datalen);
		tmdsize = datalen;
	}

	return datalen;
}

static errno_t download_tmd(void)
{
	struct DownloadState ds = {.flags = 0};
	CURLcode code;

	if ((code = curl_easy_setopt(curl, CURLOPT_URL,
			get_tmd_url())) != CURLE_OK) {
		err("curl_easy_setopt(URL:tmd): %s",
				curlerrstr(code));
		return -1;
	}

	if ((code = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ds))
			!= CURLE_OK) {
		err("curl_easy_setopt(WRITEDATA): %s",
				curlerrstr(code));
		return -1;
	}

	if ((code = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
					download_tmd_cb)) != CURLE_OK) {
		err("curl_easy_setopt(WRITEFUNCTION): %s",
				curlerrstr(code));
		return -1;
	}

	*errbuf = '\0';

	if (opts.flags & OPT_SHOW_PROGRESS)
		msg("Downloading TMD...");

	if ((code = curl_easy_perform(curl)) != CURLE_OK) {
		err("curl_easy_perform(tmd): %s",
				curlerrstr(code));
		return -1;
	}

	if (ds.flags & DS_ERROR)
		return -1;

	if (build_contents_list() != 0)
		return -1;

	return 0;
}

static inline const byte *get_common_key_from_tid(uint64_t titleid)
{
	static const byte wii_ckey[16] = {
		0xeb, 0xe4, 0x2a, 0x22, 0x5e, 0x85, 0x93, 0xe4, 0x48, 0xd9, 0xc5, 0x45, 0x73, 0x81, 0xaa, 0xf7
	};
	static const byte dsi_ckey[16] = {
		0xaf, 0x1b, 0xf5, 0x16, 0xa8, 0x07, 0xd2, 0x1a, 0xea, 0x45, 0x98, 0x4f, 0x04, 0x74, 0x28, 0x61
	};
	static const byte wiiu_ckey[16] = {
		0xd7, 0xB0, 0x04, 0x02, 0x65, 0x9b, 0xa2, 0xab, 0xd2, 0xcb, 0x0d, 0xb2, 0x7f, 0xa2, 0xb6, 0x56
	};

	switch (titleid >> 48) {
	/* Wii */
	case 0x0000:
	case 0x0001:
		return wii_ckey;
	/* Unknown, maybe reserved for DS? */
	case 0x0002:
		return NULL;
	/* DSi */
	case 0x0003:
		return dsi_ckey;
	/* 3DS */
	case 0x0004:
		/* Fuck you, 3DS bootroms. */
		return NULL;
	/* Wii U */
	case 0x0005:
		return wiiu_ckey;
	}

	return NULL;
}

static errno_t parse_cetk(void)
{
	uint32_t sigtype = ((uint32_t)cetk[0] << 24) | ((uint32_t)cetk[1] << 16)
		| ((uint32_t)cetk[2] << 8) | cetk[3];
	ssize_t offset;
	gcry_error_t gerr;
	gcry_cipher_hd_t cipher;
	const byte *common_key;
	byte iv[16];

	if ((offset = bytes_to_skip_for_signature(sigtype)) == -1) {
		err("Error: Unknown signature type %" PRIx32, sigtype);
		return -1;
	}

	/* Account for the initial four bytes used for the signature type. */
	offset += 4;

	/* The Wii and DSi use earlier versions of the Ticket schema, but the
	 * parts we care about are in the same positions.
	 */
	if (cetk[offset + 0x7c] > 0x1) {
		err("Warning: Unknown ticket version %" PRIu8 ", aborting.",
				tmd[offset + 0x40]);
		return -1;
	}

	if ((gerr = gcry_cipher_open(&cipher, GCRY_CIPHER_AES128,
					GCRY_CIPHER_MODE_CBC, 0)) != 0) {
		err("Unable to open titlekey decryption context: %s",
				gcry_strerror(gerr));
		return -1;
	}

	if ((common_key = get_common_key_from_tid(opts.titleid)) == NULL) {
		err("Error: Missing common key (unsupported/unknown platform).");
		return -1;
	}

	if ((gerr = gcry_cipher_setkey(cipher, common_key, 16)) != 0) {
		err("Unable to set common key: %s", gcry_strerror(gerr));
		gcry_cipher_close(cipher);
		return -1;
	}

	memset(iv, 0, sizeof(iv));
	/* Title ID in big endian */
	memcpy(iv, cetk + offset + 0x9c, sizeof(opts.titleid));

	if ((gerr = gcry_cipher_setiv(cipher, iv, sizeof(iv))) != 0) {
		err("Unable to set IV: %s", gcry_strerror(gerr));
		gcry_cipher_close(cipher);
		return -1;
	}

	if ((gerr = gcry_cipher_decrypt(cipher, opts.key, sizeof(opts.key),
					cetk + offset + 0x7f, sizeof(opts.key)))
			!= 0) {
		err("Unable to decrypt titlekey: %s", gcry_strerror(gerr));
		gcry_cipher_close(cipher);
		return -1;
	}

	opts.flags |= OPT_HAS_KEY;

	gcry_cipher_close(cipher);

	return 0;
}

static size_t download_cetk_cb(char *ptr, size_t size, size_t nmemb,
		void *userdata)
{
	byte *data = (byte *)ptr;
	size_t datalen = size * nmemb;

	(void)userdata;

	if (nmemb != 0 && datalen / nmemb != size) {
		err("Error: Overflow while calculating downloaded size.");
		return 0;
	}

	/* Only happens on empty file */
	if (datalen == 0) {
		err("Error: Received 0-length cetk from remote.\n"
				"Does this title have a cetk?");
		return 0;
	}

	if (cetk != NULL) {
		if (cetksize + datalen < cetksize) {
			err("Overflow while calculating downloaded size.");
			return 0;
		}

		if ((cetk = realloc(cetk, cetksize + datalen)) == NULL)
			oom();

		memcpy(cetk + cetksize, data, datalen);

		cetksize += datalen;
	} else {
		if ((cetk = malloc(datalen)) == NULL)
			oom();

		memcpy(cetk, data, datalen);
		cetksize = datalen;
	}

	return datalen;
}

static errno_t download_cetk()
{
	struct DownloadState ds = {.flags = 0};
	CURLcode code;

	if ((code = curl_easy_setopt(curl, CURLOPT_URL,
			get_cetk_url())) != CURLE_OK) {
		err("curl_easy_setopt(URL:cetk): %s",
				curlerrstr(code));
		return -1;
	}

	if ((code = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ds))
			!= CURLE_OK) {
		err("curl_easy_setopt(WRITEDATA): %s",
				curlerrstr(code));
		return -1;
	}

	if ((code = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
					download_cetk_cb)) != CURLE_OK) {
		err("curl_easy_setopt(WRITEFUNCTION): %s",
				curlerrstr(code));
		return -1;
	}

	*errbuf = '\0';

	if (opts.flags & OPT_SHOW_PROGRESS)
		msg("Downloading CETK...");

	if ((code = curl_easy_perform(curl)) != CURLE_OK) {
		err("curl_easy_perform(cetk): %s",
				curlerrstr(code));
		return -1;
	}

	if (ds.flags & DS_ERROR)
		return -1;

	if (parse_cetk() != 0)
		return -1;

	return 0;
}

static errno_t download_contents_cb_simple_crypto(
		struct DownloadCryptoContext *dcc)
{
	size_t overhang = 0;
	gcry_error_t gerr;
	struct DownloadState *ds = dcc->ds;

	/* CBC can only decrypt blockwise, but libcurl makes no promises as to
	 * how much data we get, in particular, whether it's a multiple of 16
	 * or not.
	 */
	static byte cbcbuf[16] = {0};
	static size_t cbcbuflen = 0;

	/* If we have leftover block data:
	 * - Append as much as is missing.
	 * - Decrypt that.
	 * - Write that first.
	 */
	if (cbcbuflen != 0) {
		/* Do we have enough data to fill the cbcbuf?
		 * If not, copy all data and continue next callback.
		 */
		if (cbcbuflen + dcc->datalen < sizeof(cbcbuf)) {
			memcpy(cbcbuf + cbcbuflen, dcc->data, dcc->datalen);
			cbcbuflen += dcc->datalen;

			return 0;
		}

		memcpy(cbcbuf + cbcbuflen, dcc->data, 16 - cbcbuflen);

		if ((gerr = gcry_cipher_decrypt(ds->cipher, cbcbuf,
						sizeof(cbcbuf), NULL, 0))
				!= 0) {
			err("Unable to decrypt content (%zu bytes): %s",
					16 - cbcbuflen, gcry_strerror(gerr));
			return -1;
		}

		fwrite(cbcbuf, sizeof(cbcbuf), 1, ds->f);

		/* On the Wii, at least 0001000248414241 has one content
		 * (00000043) that has more data on the CDN than the TMD
		 * indicates.
		 *
		 * Hash no more bytes than the TMD says, and discard
		 * everything else.
		 */
		if (ds->bytes_hashed + sizeof(cbcbuf) >
				ds->content->size) {
			gcry_md_write(ds->hasher, cbcbuf,
					ds->content->size - ds->bytes_hashed);

			dcc->datalen = ds->content->size - ds->bytes_hashed;
			ds->bytes_hashed += dcc->datalen;
		} else {
			gcry_md_write(ds->hasher, cbcbuf, sizeof(cbcbuf));
			ds->bytes_hashed += sizeof(cbcbuf);
		}

		dcc->data += 16 - cbcbuflen;
		dcc->datalen -= 16 - cbcbuflen;
		cbcbuflen = 0;
	}

	/* If we have data that's not aligned to a block, move the trailing
	 * part to the cbcbuf.
	 */
	if ((overhang = dcc->datalen % 16) != 0) {
		memcpy(cbcbuf, dcc->data + dcc->datalen - overhang, overhang);

		dcc->datalen -= overhang;
		cbcbuflen = overhang;
	}

	/* We might just be getting the last CBC block, and that was
	 * handled above. Check we still have things to do.
	 */
	if (dcc->datalen == 0)
		return 0;

	if ((gerr = gcry_cipher_decrypt(ds->cipher, dcc->data, dcc->datalen,
					NULL, 0)) != 0) {
		err("Unable to decrypt content (%zu bytes): %s",
				dcc->datalen, gcry_strerror(gerr));
		return -1;
	}

	if (ds->bytes_hashed + dcc->datalen > ds->content->size) {
		gcry_md_write(ds->hasher, dcc->data,
				ds->content->size - ds->bytes_hashed);
		dcc->datalen = ds->content->size - ds->bytes_hashed;
		ds->bytes_hashed += dcc->datalen;
	} else {
		gcry_md_write(ds->hasher, dcc->data, dcc->datalen);
		ds->bytes_hashed += dcc->datalen;
	}

	return 0;
}

static inline int increase_hn_counter(struct HnCounters *count)
{
	if (++count->h0 == 16) {
		count->h0 = 0;

		if (++count->h1 == 16) {
			count->h1 = 0;

			if (++count->h2 == 16) {
				err("Error: CDN content too long");
				return -1;
			}
		}
	}

	return 0;
}

static errno_t decrypt_chunk(byte *chunk, struct DownloadState *ds)
{
	gcry_error_t gerr;
	byte iv[16];
	byte digest[0x20];
	struct HnCounters *count = &ds->count;
	size_t digest_len = gcry_md_get_algo_dlen(ds->content->hashalgo);

	/* The first 0x400 bytes (meta information) are encrypted with
	 * the usual CDN crypto.
	 */
	memset(iv, 0, sizeof(iv));
	memcpy(iv, ds->content->idx, sizeof(ds->content->idx));

	if ((gerr = gcry_cipher_setiv(ds->cipher, iv, sizeof(iv))) != 0) {
		err("Unable to set IV: %s", gcry_strerror(gerr));
		return -1;
	}

	if ((gerr = gcry_cipher_decrypt(ds->cipher, chunk, CHUNK_HEADER_SIZE,
					NULL, 0)) != 0) {
		err("Unable to decrypt chunk header: %s", gcry_strerror(gerr));
		return -1;
	}

	chunk[0] ^= ds->content->idx[0];
	chunk[1] ^= ds->content->idx[1];

	/* Verify H2 against H3 from the TMD. H2 cannot change because
	 * H3 is fixated in the TMD.
	 */
	gcry_md_hash_buffer(ds->content->hashalgo, digest, chunk + 0x280,
			HN_SIZE);
	if (memcmp(digest, ds->content->h3, digest_len) != 0) {
		err("Error: H3 mismatch for content %08" PRIx32 ".",
				ds->content->contentid);
		return -1;
	}

	/* Verify H1 against current H2 */
	gcry_md_hash_buffer(ds->content->hashalgo, digest, chunk + 0x140,
			HN_SIZE);
	if (memcmp(digest, chunk + 0x280 + (count->h2 * digest_len), digest_len)
			!= 0) {
		err("Error: H2 mismatch for content %08" PRIx32 ".",
				ds->content->contentid);
		return -1;
	}

	/* Verify H0 against current H1 */
	gcry_md_hash_buffer(ds->content->hashalgo, digest, chunk, HN_SIZE);

	if (memcmp(digest, chunk + 0x140 + (count->h1 * digest_len), digest_len)
			!= 0) {
		err("Error: H1 mismatch for content %08" PRIx32 ".",
				ds->content->contentid);
		return -1;
	}

	/* Decrypt the actual data */
	memcpy(iv, chunk + (count->h0 * digest_len), sizeof(iv));

	if ((gerr = gcry_cipher_setiv(ds->cipher, iv, sizeof(iv))) != 0) {
		err("Unable to set IV: %s", gcry_strerror(gerr));
		return -1;
	}

	if ((gerr = gcry_cipher_decrypt(ds->cipher, chunk + CHUNK_HEADER_SIZE,
					BLOCK_SIZE, NULL, 0))
			!= 0) {
		err("Unable to decrypt data block: %s",
				gcry_strerror(gerr));
		return -1;
	}

	/* Verify data against current H0 */
	gcry_md_hash_buffer(ds->content->hashalgo, digest,
			chunk + CHUNK_HEADER_SIZE, BLOCK_SIZE);

	if (memcmp(digest, chunk + (count->h0 * digest_len), digest_len) != 0) {
		err("Error: H0 mismatch for content %08" PRIx32 ".",
				ds->content->contentid);
		return -1;
	}

	if (increase_hn_counter(count) != 0)
		return -1;

	return 0;
}

static errno_t download_contents_cb_blockwise_crypto(
		struct DownloadCryptoContext *dcc)
{
	size_t overhang;

	static byte chunk[CHUNK_SIZE];
	static size_t filled;

	if (dcc->datalen + filled < sizeof(chunk)) {
		memcpy(chunk + filled, dcc->data, dcc->datalen);
		filled += dcc->datalen;
		return 0;
	}

	/* We have more than or exactly enough data to fill the chunk. */
	overhang = dcc->datalen + filled - sizeof(chunk);

	memcpy(chunk + filled, dcc->data, dcc->datalen - overhang);

	if (decrypt_chunk(chunk, dcc->ds) != 0)
		return -1;

	if (overhang > 0)
		memcpy(chunk, dcc->data + dcc->datalen - overhang, overhang);

	filled = overhang;
	dcc->datalen = 0;

	fwrite(chunk, sizeof(chunk), 1, dcc->ds->f);

	return 0;
}

static size_t download_contents_cb(char *ptr, size_t size, size_t nmemb,
		void *userdata)
{
	struct DownloadState *ds = userdata;
	struct DownloadCryptoContext dcc;
	byte *data = (byte *)ptr;
	size_t datalen = size * nmemb;
	size_t real_datalen = datalen;

	if (nmemb != 0 && datalen / nmemb != size) {
		ds->flags |= DS_ERROR;
		err("Error: Overflow while calculating downloaded size.");
		return 0;
	}

	/* Only happens on empty file */
	if (datalen == 0) {
		ds->flags |= DS_ERROR;
		err("Error: Received 0-length content from remote.");
		return 0;
	}

	if ((opts.flags & OPT_HAS_KEY)) {
		dcc.data = data;
		dcc.datalen = datalen;
		dcc.ds = ds;

		if (has_simple_crypto(ds->content)) {
			if (download_contents_cb_simple_crypto(&dcc) != 0)
				return 0;
		} else if (ds->content->type & TYPE_BLOCKWISECRYPTO) {
			if (download_contents_cb_blockwise_crypto(&dcc) != 0)
				return 0;

			return real_datalen;
		} else {
			/* XXX: Assuming there's always encryption. */
			err("Error: Unknown encryption for title.");
			return 0;
		}

		datalen = dcc.datalen;
		data = dcc.data;
	}

	/* We might just be getting the last CBC block, and that was
	 * handled above. Check we still have things to do.
	 */
	if (datalen > 0)
		fwrite(data, datalen, 1, ds->f);

	if (ferror(ds->f))
		/* Signals an error to libcurl and aborts the transfer. */
		return 0;

	return real_datalen;
}

static inline int get_hash_algo_from_tid(uint64_t titleid)
{
	switch (titleid >> 48) {
	/* Wii */
	case 0x0000:
	case 0x0001:
		return GCRY_MD_SHA1;
	/* Unknown, maybe reserved for DS? */
	case 0x0002:
		return -1;
	/* DSi */
	case 0x0003:
		return GCRY_MD_SHA1;
	/* 3DS */
	case 0x0004:
		return GCRY_MD_SHA256;
	/* Wii U */
	case 0x0005:
		/* What the fuck? */
		return GCRY_MD_SHA1;
	}

	return -1;
}

static size_t download_and_verify_h3_cb(char *ptr, size_t size, size_t nmemb,
		void *userdata)
{
	struct Content *content = userdata;
	size_t datalen = size * nmemb;

	if (nmemb != 0 && datalen / nmemb != size) {
		err("Error: Overflow while calculating downloaded size.");
		return 0;
	}

	/* Only happens on empty file */
	if (datalen == 0) {
		err("Error: Received 0-length content from remote.");
		return 0;
	}

	if (datalen > sizeof(content->h3)) {
		err("Error: Received oversized H3, expected max 0x%zx bytes.",
				sizeof(content->h3));
		return 0;
	}

	memcpy(content->h3, ptr, datalen);

	return datalen;
}

static errno_t download_and_verify_h3(struct Content *content)
{
	CURLcode code;
	byte digest[0x20];

	if ((code = curl_easy_setopt(curl, CURLOPT_WRITEDATA, content))
			!= CURLE_OK) {
		err("curl_easy_setopt(WRITEDATA): %s",
				curlerrstr(code));
		return -1;
	}

	if ((code = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
					download_and_verify_h3_cb))
			!= CURLE_OK) {
		err("curl_easy_setopt(WRITEFUNCTION): %s",
				curlerrstr(code));
		return -1;
	}

	if ((code = curl_easy_setopt(curl, CURLOPT_URL,
			get_h3_url_for_content(content))) != CURLE_OK) {
		err("curl_easy_setopt(URL:%08" PRIx32 ".h3): %s",
				content->contentid, curlerrstr(code));
		return -1;
	}

	if (opts.flags & OPT_SHOW_PROGRESS)
		msg("Downloading H3 for content %08" PRIx32 "...",
				content->contentid);

	*errbuf = '\0';

	if ((code = curl_easy_perform(curl)) != CURLE_OK) {
		err("curl_easy_perform(%08" PRIx32 ".h3): %s",
				content->contentid, curlerrstr(code));
		return -1;
	}

	gcry_md_hash_buffer(content->hashalgo, digest, content->h3,
			gcry_md_get_algo_dlen(content->hashalgo));

	if (memcmp(content->hash, digest,
				gcry_md_get_algo_dlen(content->hashalgo))
			!= 0) {
		err("Error: Hash mismatch for H3 of content "
				"%08" PRIx32,
				content->contentid);
		return -1;
	}

	return 0;
}

static errno_t prepare_crypto_for_download(struct DownloadState *ds)
{
	gcry_error_t gerr;
	byte iv[16] = {0};

	if (has_simple_crypto(ds->content)) {
		memcpy(iv, ds->content->idx, sizeof(ds->content->idx));

		if ((gerr = gcry_cipher_setiv(ds->cipher, iv, sizeof(iv)))
				!= 0) {
			err("Unable to set IV: %s",
					gcry_strerror(gerr));
			return -1;
		}
	} else if (ds->content->type & TYPE_BLOCKWISECRYPTO) {
		if (download_and_verify_h3(ds->content) != 0)
			return -1;
	}

	return 0;
}

static errno_t download_content(struct Content *content,
		struct DownloadState *ds)
{
	FILE *f;
	uint64_t filelen;
	char filename[9];
	CURLcode code;

	if ((opts.flags & OPT_HAS_KEY)) {
		if (prepare_crypto_for_download(ds) != 0)
			return -1;
	}

	if ((code = curl_easy_setopt(curl, CURLOPT_URL,
			get_content_url(content))) != CURLE_OK) {
		err("curl_easy_setopt(URL:%08" PRIx32 "): %s",
				content->contentid, curlerrstr(code));
		return -1;
	}

	snprintf(filename, sizeof(filename), "%08x", content->contentid);

	errno = 0;
	if ((f = fopen(filename, "wb")) == NULL) {
		err("Unable to open %s for writing: %s", filename,
				strerror(errno));
		return -1;
	}

	ds->f = f;

	if (opts.flags & OPT_SHOW_PROGRESS)
		msg("Downloading content %08" PRIx32 "...",
				content->contentid);

	if ((code = curl_easy_setopt(curl, CURLOPT_WRITEDATA, ds))
			!= CURLE_OK) {
		err("curl_easy_setopt(WRITEDATA): %s",
				curlerrstr(code));
		fclose(f);
		return -1;
	}

	if ((code = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
					download_contents_cb))
			!= CURLE_OK) {
		err("curl_easy_setopt(WRITEFUNCTION): %s",
				curlerrstr(code));
		fclose(f);
		return -1;
	}

	*errbuf = '\0';

	if ((code = curl_easy_perform(curl)) != CURLE_OK) {
		err("curl_easy_perform(%08" PRIx32 "): %s",
				content->contentid, curlerrstr(code));
		fclose(f);
		return -1;
	}

	fclose(f);

	if (util_get_file_size(filename, &filelen) == 0
			&& filelen != content->size) {
		err("Warning: File size mismatch (got %" PRIu64
				" vs. expected %" PRIu64
				") for content %08" PRIx32,
				filelen,
				content->size,
				content->contentid);
	}

	if (ds->flags & DS_ERROR)
		return -1;

	if (!(opts.flags & OPT_HAS_KEY))
		return 0;

	/* TMD SHA-1/hash tree-based verification happened as part of the
	 * decryption for blockwise crypto contents.
	 */
	if (has_simple_crypto(content)) {
		gcry_md_final(ds->hasher);

		if (memcmp(gcry_md_read(ds->hasher, content->hashalgo),
					content->hash,
					gcry_md_get_algo_dlen(content->hashalgo))
				!= 0) {
			err("Error: Hash mismatch for content %08" PRIx32,
					content->contentid);
			return -1;
		}
	}

	gcry_cipher_reset(ds->cipher);
	gcry_md_reset(ds->hasher);

	return 0;
}

static errno_t download_contents(void)
{
	struct DownloadState ds;
	int hashalgo = 0;
	gcry_error_t gerr;
	errno_t ret = 0;

	memset(&ds, 0, sizeof(ds));

	if (opts.flags & OPT_HAS_KEY) {
		if ((gerr = gcry_cipher_open(&ds.cipher, GCRY_CIPHER_AES128,
						GCRY_CIPHER_MODE_CBC, 0))
				!= 0) {
			err("Unable to open decryption context: %s",
					gcry_strerror(gerr));
			return -1;
		}

		if ((gerr = gcry_cipher_setkey(ds.cipher, opts.key,
						sizeof(opts.key))) != 0) {
			err("Unable to set key: %s",
					gcry_strerror(gerr));
			gcry_cipher_close(ds.cipher);
			return -1;
		}

		if ((hashalgo = get_hash_algo_from_tid(opts.titleid)) == -1) {
			err("Unknown platform for title ID %016" PRIu64,
					opts.titleid);
			gcry_cipher_close(ds.cipher);
			return -1;
		}

		if ((gerr = gcry_md_open(&ds.hasher, hashalgo, 0))
				!= 0) {
			err("Unable to open hasher: %s",
					gcry_strerror(gerr));
			gcry_cipher_close(ds.cipher);
			return -1;
		}
	}

	for (struct Content *content = contents;
			content != NULL;
			content = content->next) {
		ds.content = content;
		ds.bytes_hashed = 0;
		memset(&ds.count, 0, sizeof(ds.count));
		content->hashalgo = hashalgo;

		if (download_content(content, &ds) != 0)
			break;
	}

	if (opts.flags & OPT_HAS_KEY) {
		gcry_cipher_close(ds.cipher);
		gcry_md_close(ds.hasher);
	}

	return ret;
}

static void free_contents_list()
{
	struct Content *cur, *next;

	for (cur = contents, next = cur->next; cur != NULL; cur = next, next = cur ? cur->next : NULL) {
		free(cur);
	}
}
static void download_fini(void)
{
	free_contents_list();
	curl_easy_cleanup(curl);
}

errno_t download_title(void)
{
	errno_t ret;

	if ((ret = download_init()) != 0)
		return ret;

	if ((ret = download_tmd()) != 0)
		return ret;

	if (opts.flags & OPT_DECRYPT_FROM_CETK) {
		if ((ret = download_cetk()) != 0)
			return ret;
	}

	if ((ret = download_contents()) != 0)
		return ret;

	download_fini();

	return 0;
}

