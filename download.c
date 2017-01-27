#ifdef __WIN32
	#define CURL_STATICLIB
#endif

#include <curl/curl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "crypto.h"
#include "main.h"
#include "download.h"
#include "types.h"
#include "util.h"

#ifdef _WIN32
	#define CURL_INIT_VARS CURL_GLOBAL_WIN32
#else
	#define CURL_INIT_VARS CURL_GLOBAL_NOTHING
#endif

static CURL *curl;
static char errbuf[CURL_ERROR_SIZE];

static byte *tmd = NULL;
static size_t tmdsize;
static byte *cetk = NULL;
static size_t cetksize;
static uint8_t common_key_index;
static struct Content *contents = NULL;

static const char *curlerrstr(CURLcode code)
{
	if (*errbuf)
		return errbuf;
	else
		return curl_easy_strerror(code);
}

static const char *get_cdn_base_url(void)
{
	const char *ret;

	if ((ret = getenv("NUSTOOL_BASE_URL")) == NULL)
		ret = DEFAULT_NUS_BASE_URL;

	return ret;
}

static char *get_base_url_for_titleid(uint64_t titleid)
{
	size_t len;
	const char *baseurl;
	char *urlbuf;

	baseurl = get_cdn_base_url();

	/* baseurl + "/0000000000000000/" */
	len = strlen(baseurl) + 18;

	urlbuf = malloc(len + 1);

	sprintf(urlbuf, "%s/%016" PRIx64 "/", baseurl, titleid);

	return urlbuf;
}

static char *get_tmd_url(void)
{
	char *urlbuf;

	if ((urlbuf = get_base_url_for_titleid(opts.titleid)) == NULL)
		return NULL;

	if (opts.flags & OPT_HAS_VERSION)
		return util_realloc_and_append_fmt(urlbuf, 9, "tmd.%" PRIu16,
				opts.version);
	else
		return util_realloc_and_append_fmt(urlbuf, 3, "%s", "tmd");
}

static char *get_cetk_url(void)
{
	char *urlbuf;

	if ((urlbuf = get_base_url_for_titleid(opts.titleid)) == NULL)
		return NULL;

	return util_realloc_and_append_fmt(urlbuf, 4, "%s", "cetk");
}

static char *get_content_url(const struct Content *content)
{
	char *urlbuf;

	if ((urlbuf = get_base_url_for_titleid(opts.titleid)) == NULL)
		return NULL;

	return util_realloc_and_append_fmt(urlbuf, 8, "%08" PRIx32,
			content->contentid);
}

static char *get_h3_url_for_content(const struct Content *content)
{
	char *urlbuf;

	if ((urlbuf = get_base_url_for_titleid(opts.titleid)) == NULL)
		return NULL;

	return util_realloc_and_append_fmt(urlbuf, 11, "%08" PRIx32 ".h3",
			content->contentid);
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

	/* Create output directory, if relevant. */
	if (!(opts.flags & OPT_LOCAL_FILES) && util_create_outdir() != 0) {
		err("Failed to create output directory");
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

static errno_t write_file_from_memory(const char *filename,
		void *data, size_t datalen)
{
	FILE *f;

	char *filepath = util_get_filepath(filename);

	/* We may get an attempt to write a 0-len cetk if we run with -m and
	 * download a title that has no cetk.
	 */
	if (datalen == 0)
		return 0;

	if ((f = fopen(filepath, "wb")) == NULL) {
		err("Unable to open %s for writing: %s", filepath,
				strerror(errno));
		free(filepath);
		return -1;
	}

	fwrite(data, datalen, 1, f);

	fclose(f);
	free(filepath);

	return 0;
}

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
	char *url;

	if ((url = get_tmd_url()) == NULL) {
		oom();
		return -1;
	}

	if ((code = curl_easy_setopt(curl, CURLOPT_URL, url)) != CURLE_OK) {
		err("curl_easy_setopt(URL:tmd): %s",
				curlerrstr(code));
		free(url);
		return -1;
	}

	if ((code = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ds))
			!= CURLE_OK) {
		err("curl_easy_setopt(WRITEDATA): %s",
				curlerrstr(code));
		free(url);
		return -1;
	}

	if ((code = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
					download_tmd_cb)) != CURLE_OK) {
		err("curl_easy_setopt(WRITEFUNCTION): %s",
				curlerrstr(code));
		free(url);
		return -1;
	}

	*errbuf = '\0';

	if (opts.flags & OPT_SHOW_PROGRESS)
		msg("Downloading TMD...");

	if ((code = curl_easy_perform(curl)) != CURLE_OK) {
		err("curl_easy_perform(tmd): %s",
				curlerrstr(code));
		free(url);
		return -1;
	}

	free(url);

	if (ds.flags & DS_ERROR)
		return -1;

	if (build_contents_list() != 0)
		return -1;

	return 0;
}

static inline const byte *get_common_keyY_ctr(uint64_t titleid, bool is_retail)
{
	/* The 3DS uses a field in the ticket to determine which keyY to use.
	 *
	 * Normally, only 0 (application, e.g. from eShop) and 1 (system title)
	 * are used. Appearances of the other keyYs haven't been spotted.
	 *
	 * However, we may be provided the encrypted titlekey from -K only. In
	 * that case, we have no ticket, so we'll just test if TIDhigh bit 0x10,
	 * which indicates a system title, is set.
	 */
	static const byte ctr_ckeyYs[6][16] = {
		{0xd0, 0x7b, 0x33, 0x7f, 0x9c, 0xa4, 0x38, 0x59, 0x32, 0xa2, 0xe2, 0x57, 0x23, 0x23, 0x2e, 0xb9},
		{0x0c, 0x76, 0x72, 0x30, 0xf0, 0x99, 0x8f, 0x1c, 0x46, 0x82, 0x82, 0x02, 0xfa, 0xac, 0xbe, 0x4c},
		{0xc4, 0x75, 0xcb, 0x3a, 0xb8, 0xc7, 0x88, 0xbb, 0x57, 0x5e, 0x12, 0xa1, 0x09, 0x07, 0xb8, 0xa4},
		{0xe4, 0x86, 0xee, 0xe3, 0xd0, 0xc0, 0x9c, 0x90, 0x2f, 0x66, 0x86, 0xd4, 0xc0, 0x6f, 0x64, 0x9f},
		{0xed, 0x31, 0xba, 0x9c, 0x04, 0xb0, 0x67, 0x50, 0x6c, 0x44, 0x97, 0xa3, 0x5b, 0x78, 0x04, 0xfc},
		{0x5e, 0x66, 0x99, 0x8a, 0xb4, 0xe8, 0x93, 0x16, 0x06, 0x85, 0x0f, 0xd7, 0xa1, 0x6d, 0xd7, 0x55}
	};
	/* Titles that use keyY#0 (application) use a different keyY in the
	 * development environment.
	 *
	 * (Technically, the 3DS firmware uses a hardcoded normalkey, rather
	 * than computing it from keyX and keyY, but we do it differently here
	 * for the sake of having less branching.)
	 */
	static const byte ctr_ckeyY_dev_app[16] = {
		0x85, 0x21, 0x5e, 0x96, 0xcb, 0x95, 0xa9, 0xec, 0xa4, 0xb4, 0xde, 0x60, 0x1c, 0xb5, 0x62, 0xc7
	};

	if (cetksize == 0) {
		if ((titleid >> 32) & 0x10)
			common_key_index = 1;
		else
			common_key_index = 0;
	}

	if (common_key_index > 5) {
		err("Error: Unknown 3DS common keyY index %" PRIu8 "?!",
				common_key_index);
		return NULL;
	}

	if (!is_retail && common_key_index == 0)
		return ctr_ckeyY_dev_app;
	else
		return ctr_ckeyYs[common_key_index];
}

static inline const byte *get_common_key_ctr(uint64_t titleid,
		bool is_retail)
{
	/* missing: ctr_ckeyX_retail */
	static const byte ctr_ckeyX_dev[16] = {
		0xbd, 0x4f, 0xe7, 0xe7, 0x33, 0xc7, 0x55, 0xfc, 0xe7, 0x54, 0x0e, 0xab, 0xbd, 0x8a, 0xc3, 0x0d
	};

	static byte ckey[16];
	const byte *keyY;

	if (is_retail)
		/* Fuck you, 3DS bootroms. */
		return NULL;

	if ((keyY = get_common_keyY_ctr(titleid, is_retail)) == NULL)
		return NULL;

	return crypto_ctr_key_scramble(ckey, ctr_ckeyX_dev, keyY);
}

static inline const byte *get_common_key(uint64_t titleid, bool is_retail)
{
	static const byte wii_ckey_retail[16] = {
		0xeb, 0xe4, 0x2a, 0x22, 0x5e, 0x85, 0x93, 0xe4, 0x48, 0xd9, 0xc5, 0x45, 0x73, 0x81, 0xaa, 0xf7
	};
	static const byte dsi_ckey_retail[16] = {
		0xaf, 0x1b, 0xf5, 0x16, 0xa8, 0x07, 0xd2, 0x1a, 0xea, 0x45, 0x98, 0x4f, 0x04, 0x74, 0x28, 0x61
	};
	static const byte wiiu_ckey_retail[16] = {
		0xd7, 0xb0, 0x04, 0x02, 0x65, 0x9b, 0xa2, 0xab, 0xd2, 0xcb, 0x0d, 0xb2, 0x7f, 0xa2, 0xb6, 0x56
	};
	static const byte wii_ckey_dev[16] = {
		0xa1, 0x60, 0x4a, 0x6a, 0x71, 0x23, 0xb5, 0x29, 0xae, 0x8b, 0xec, 0x32, 0xc8, 0x16, 0xfc, 0xaa
	};
	static const byte wiiu_ckey_dev[16] = {
		0x2f, 0x5c, 0x1b, 0x29, 0x44, 0xe7, 0xfd, 0x6f, 0xc3, 0x97, 0x96, 0x4b, 0x05, 0x76, 0x91, 0xfa
	};

	switch (titleid >> 48) {
	/* Wii */
	case 0x0000:
	case 0x0001:
		return (is_retail ? wii_ckey_retail : wii_ckey_dev);
	/* Unknown, maybe reserved for DS? */
	case 0x0002:
		return NULL;
	/* DSi */
	case 0x0003:
		/* DSi and Wii share their dev common keys. */
		return (is_retail ? dsi_ckey_retail : wii_ckey_dev);
	/* 3DS */
	case 0x0004:
		return get_common_key_ctr(titleid, is_retail);
	/* Wii U */
	case 0x0005:
		return (is_retail ? wiiu_ckey_retail : wiiu_ckey_dev);
	}

	return NULL;
}

static errno_t decrypt_titlekey(void)
{
	gcry_error_t gerr;
	gcry_cipher_hd_t cipher;
	const byte *common_key;
	byte iv[16];
	uint64_t bits;

	if ((gerr = gcry_cipher_open(&cipher, GCRY_CIPHER_AES128,
					GCRY_CIPHER_MODE_CBC, 0)) != 0) {
		err("Unable to open titlekey decryption context: %s",
				gcry_strerror(gerr));
		return -1;
	}

	if ((common_key = get_common_key(opts.titleid,
					!(opts.flags & OPT_DEV_KEYS))) == NULL) {
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
	for (size_t i = 0; i < sizeof(opts.titleid); ++i) {
		bits = (8 * (sizeof(opts.titleid) - 1 - i));
		iv[i] = (opts.titleid & (0xFFLLU << bits)) >> bits;
	}

	if ((gerr = gcry_cipher_setiv(cipher, iv, sizeof(iv))) != 0) {
		err("Unable to set IV: %s", gcry_strerror(gerr));
		gcry_cipher_close(cipher);
		return -1;
	}

	if ((gerr = gcry_cipher_decrypt(cipher, opts.key, sizeof(opts.key),
					NULL, 0))
			!= 0) {
		err("Unable to decrypt titlekey: %s", gcry_strerror(gerr));
		gcry_cipher_close(cipher);
		return -1;
	}

	gcry_cipher_close(cipher);

	opts.flags |= OPT_HAS_KEY;
	opts.flags &= ~OPT_KEY_ENCRYPTED;

	return 0;
}

static errno_t parse_cetk(void)
{
	uint32_t sigtype = ((uint32_t)cetk[0] << 24) | ((uint32_t)cetk[1] << 16)
		| ((uint32_t)cetk[2] << 8) | cetk[3];
	ssize_t offset;
	uint64_t titleid = 0;

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
				cetk[offset + 0x7c]);
		return -1;
	}

	for (size_t i = 0; i < sizeof(titleid); ++i)
		titleid |= (uint64_t)(cetk[offset + 0x9c +
				sizeof(titleid) - 1 - i]) << (8 * i);

	opts.titleid = titleid;
	memcpy(opts.key, cetk + offset + 0x7f, sizeof(opts.key));

	common_key_index = cetk[offset + 0xb1];

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

static errno_t download_cetk(void)
{
	struct DownloadState ds = {.flags = 0};
	CURLcode code;
	long response_code;
	char *url;

	if ((url = get_cetk_url()) == NULL) {
		oom();
		return -1;
	}

	if ((code = curl_easy_setopt(curl, CURLOPT_URL, url)) != CURLE_OK) {
		err("curl_easy_setopt(URL:cetk): %s",
				curlerrstr(code));
		free(url);
		return -1;
	}

	if ((code = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ds))
			!= CURLE_OK) {
		err("curl_easy_setopt(WRITEDATA): %s",
				curlerrstr(code));
		free(url);
		return -1;
	}

	if ((code = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
					download_cetk_cb)) != CURLE_OK) {
		err("curl_easy_setopt(WRITEFUNCTION): %s",
				curlerrstr(code));
		free(url);
		return -1;
	}

	*errbuf = '\0';

	if (opts.flags & OPT_SHOW_PROGRESS)
		msg("Downloading CETK...");

	if ((code = curl_easy_perform(curl)) != CURLE_OK) {
		free(url);

		/* We may be downloading a cetk due to -m, despite not wanting
		 * to decrypt the title. However, this operation can, of course,
		 * fail for titles that don't have cetk.
		 *
		 * Check if the failure is just a 404 (and not, say, a network
		 * problem) and if we don't *need* the cetk.
		 */
		if ((code = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE,
						&response_code)) != CURLE_OK) {
			err("curl_easy_getinfo(cetk): %s",
					curlerrstr(code));
			return -1;
		}

		if (response_code != 404
				|| (opts.flags & OPT_DECRYPT_FROM_CETK)) {
			err("curl_easy_perform(cetk): %s",
					curlerrstr(code));
			return -1;
		}

		/* If we did fail but fallthrough, the progress bar will
		 * break the output on failure.
		 */
		if (opts.flags & OPT_SHOW_PROGRESS)
			printf("\n");
	} else { /* Wrap free in else block to prevent doublefree on fallthrough. */
		free(url);
	}

	if (ds.flags & DS_ERROR)
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

	/* If we are reading state from a partial file, do not re-apply
	 * the decryption step (or we'll actually break the hash!),
	 * only fill the hasher.
	 *
	 * However, because the CDN encryption uses AES in CBC mode, we need to
	 * set the IV to match the state we've been downloading if we're
	 * decrypting.
	 *
	 * In CBC decryption, the previous *ciphertext* is xored with the
	 * current AES plaintext. Since we've written plaintext, we need to
	 * re-encrypt everything up to this point to obtain the current IV.
	 */
	gcry_error_t (*cipher_func)(gcry_cipher_hd_t h, void *out,
			size_t outsize, const void *in, size_t inlen) =
		(ds->flags & DS_RESUMING
			? gcry_cipher_encrypt
			: gcry_cipher_decrypt);

	/* If we have leftover block data:
	 * - Append as much as is missing.
	 * - Decrypt that.
	 * - Write that first.
	 *
	 * This cannot happen when reading state back from a partially
	 * downloaded file since we only write to file when we have a complete
	 * AES block already.
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

	/* If we're downloading and decrypting, we need to *decrypt* in CBC
	 * mode and feed the decrypted contents to the hasher.
	 *
	 * If we're resuming a download, we need to *encrypt* in CBC mode to
	 * make sure we're continuing from the right IV, but thta breaks
	 * dcc->data being plaintext, so we need to hash first and then encrypt.
	 */
#define HASH() do {\
	if (ds->bytes_hashed + dcc->datalen > ds->content->size) {\
		gcry_md_write(ds->hasher, dcc->data,\
				ds->content->size - ds->bytes_hashed);\
		dcc->datalen = ds->content->size - ds->bytes_hashed;\
		ds->bytes_hashed += dcc->datalen;\
	} else {\
		gcry_md_write(ds->hasher, dcc->data, dcc->datalen);\
		ds->bytes_hashed += dcc->datalen;\
	}\
} while (0)
#define CRYPT() do {\
	if ((gerr = (*cipher_func)(ds->cipher,\
					dcc->data, dcc->datalen,\
					NULL, 0)) != 0) {\
		err("Unable to crypt content (%zu bytes): %s",\
				dcc->datalen, gcry_strerror(gerr));\
		return -1;\
	}\
} while (0)

	if (ds->flags & DS_RESUMING) {
		HASH();
		CRYPT();
	} else {
		CRYPT();
		HASH();
	}

#undef HASH
#undef CRYPT

	return 0;
}

static inline errno_t increase_hn_counter(struct HnCounters *count)
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

	/* We have more than or exactly enough data to fill the chunk.
	 *
	 * If resuming, we only need to bump the Hn counters, since the
	 * encryption is stateless between individual chunks.
	 */
	if (dcc->ds->flags & DS_RESUMING) {
		increase_hn_counter(&dcc->ds->count);
		return 0;
	}

	overhang = dcc->datalen + filled - sizeof(chunk);

	memcpy(chunk + filled, dcc->data, dcc->datalen - overhang);

	if (decrypt_chunk(chunk, dcc->ds) != 0)
		return -1;

	if (overhang > 0)
		memcpy(chunk, dcc->data + dcc->datalen - overhang, overhang);

	filled = overhang;
	dcc->datalen = 0;

	if (!(dcc->ds->flags & DS_RESUMING))
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

	if (opts.flags & OPT_HAS_KEY) {
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
			/* XXX: Assuming there's always encryption.
			 *
			 * The CDN seems to really only operate with encrypted
			 * titles, though.
			 *
			 * This *may* be different for dev CDN(s), but no such
			 * thing has been seen in the wild thus far.
			 */
			err("Error: Unknown encryption for title.");
			return 0;
		}

		datalen = dcc.datalen;
		data = dcc.data;
	}

	/* We might just be getting the last CBC block, and that was
	 * handled above. Check we still have things to do.
	 */
	if (datalen > 0 && !(ds->flags & DS_RESUMING))
		fwrite(data, datalen, 1, ds->f);

	if (ferror(ds->f)) {
		err("I/O error when reading/writing file");
		/* Signals an error to libcurl and aborts the transfer. */
		return 0;
	}

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
	char *url;

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

	if ((url = get_h3_url_for_content(content)) == NULL) {
		oom();
		return -1;
	}

	if ((code = curl_easy_setopt(curl, CURLOPT_URL, url)) != CURLE_OK) {
		err("curl_easy_setopt(URL:%08" PRIx32 ".h3): %s",
				content->contentid, curlerrstr(code));
		free(url);
		return -1;
	}

	if (opts.flags & OPT_SHOW_PROGRESS)
		msg("Downloading H3 for content %08" PRIx32 "...",
				content->contentid);

	*errbuf = '\0';

	if ((code = curl_easy_perform(curl)) != CURLE_OK) {
		err("curl_easy_perform(%08" PRIx32 ".h3): %s",
				content->contentid, curlerrstr(code));
		free(url);
		return -1;
	}

	free(url);

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

/* Side effect: Moves the FILE* to the end of file so that appending works
 * transparently as though a new download had begun.
 */
static errno_t read_partial_file_into_state(struct DownloadState *ds)
{
	CURLcode code;
	/* Avoids having to deal with partial chunks for contents using
	 * blockwise crypto.
	 */
	static byte buf[CHUNK_SIZE];
	size_t bytes_read;
	size_t filelen;
	char filename[9];
	char *filepath;

	snprintf(filename, sizeof(filename), "%08x", ds->content->contentid);
	filepath = util_get_filepath(filename);

	/* File not being found is *not* okay -- we may have just created it
	 * with the fopen(..., "w+b") call in download_content().
	 *
	 * File being empty, however, is.
	 */
	if (util_get_file_size(filepath, &filelen) != 0)
		return -1;

	if (filelen == 0)
		return 0;

	if (filelen > ds->content->size) {
		err("Content size (%" PRIu64 ") is greater than size of"
				" local file (%08" PRIx32 ": %" PRIu64 "."
				" Broken resume; refusing to continue.",
				ds->content->size, ds->content->contentid,
				filelen);
		return -1;
	}

	if (filelen == ds->content->size && (opts.flags & OPT_SHOW_PROGRESS)) {
		msg("Skipping already downloaded content %08" PRIx32 ".",
				ds->content->contentid);
		return 1;
	}

	ds->flags |= DS_RESUMING;

	while ((bytes_read = fread(buf, 1, sizeof(buf), ds->f)) != 0) {
		/* CURL uses a different return code convention, where a return
		 * value of less than the total amount of data the function was
		 * called with signifies an error.
		 *
		 * Since we're using our internal download callback function,
		 * expect this kind of return value here.
		 */
		if (download_contents_cb((char *)buf, 1, bytes_read, ds)
				!= bytes_read)
			return -1;
	}

	if (ferror(ds->f)) {
		err("Reading file failed: %s", strerror(errno));
		return -1;
	}

	ds->flags &= ~DS_RESUMING;

	/* Guard against libcurl compiled with < 64-bit curl_off_t if the input
	 * is beyond that size.
	 *
	 * curl_off_t is a signed type and overflowing that is undefined
	 * behavior.
	 *
	 * XXX: We assume in the entire program, top to bottom, that the program
	 * is running on a machine CHAR_BIT == 8.
	 *
	 * There's no macro for the maximum value provided by libcurl, so we'll
	 * have to work with the size the type (which *is* provided). 8 times
	 * the size of the type yields the number of bits in the type. We need
	 * to subtract 2 from that; one because 1 << bit_size is always an
	 * overflow and another because 1 << (bit_size - 1) is an overflow on
	 * signed integers, and curl_off_t is a signed type.
	 */
	if (8 * CURL_SIZEOF_CURL_OFF_T - 2 <= util_get_msb64(filelen)) {
		err("File %08" PRIx32 " too large for your platform to resume.",
				ds->content->contentid);
		return -1;
	}

	if ((code = curl_easy_setopt(curl, CURLOPT_RESUME_FROM_LARGE,
			(curl_off_t)filelen)) != CURLE_OK) {
		err("curl_easy_setopt(URL:%08" PRIx32 "): %s",
				ds->content->contentid, curlerrstr(code));
		return -1;
	}

	if (opts.flags & OPT_SHOW_PROGRESS)
		msg("Resuming download from byte %" PRIu64 ".", filelen);

	return 0;
}

static errno_t download_content(struct DownloadState *ds)
{
	FILE *f;
	uint64_t filelen;
	char filename[9];
	CURLcode code;
	char *url;
	char *filepath;

	snprintf(filename, sizeof(filename), "%08x", ds->content->contentid);

	filepath = util_get_filepath(filename);

	errno = 0;
	/* Since r+b won't create the file, but we need the file pointer at the
	 * beginning of the file, we'll just manually create the file.
	 */
	if (util_create_file(filepath) != 0) {
		err("Unable to create file %s: %s", filepath, strerror(errno));
		free(filepath);
		return -1;
	}

	errno = 0;
	if ((f = fopen(filepath, "r+b")) == NULL) {
		err("Unable to open %s for reading and writing: %s", filepath,
				strerror(errno));
		free(filepath);
		return -1;
	}

	ds->f = f;

	if (opts.flags & OPT_HAS_KEY) {
		if (prepare_crypto_for_download(ds) != 0) {
			free(filepath);
			return -1;
		}
	}

	if ((url = get_content_url(ds->content)) == NULL) {
		oom();
		free(filepath);
		return -1;
	}

	if ((code = curl_easy_setopt(curl, CURLOPT_URL, url)) != CURLE_OK) {
		err("curl_easy_setopt(URL:%08" PRIx32 "): %s",
				ds->content->contentid, curlerrstr(code));
		free(url);
		free(filepath);
		return -1;
	}

	if ((code = curl_easy_setopt(curl, CURLOPT_WRITEDATA, ds))
			!= CURLE_OK) {
		err("curl_easy_setopt(WRITEDATA): %s",
				curlerrstr(code));
		free(url);
		fclose(f);
		free(filepath);
		return -1;
	}

	if ((code = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
					download_contents_cb))
			!= CURLE_OK) {
		err("curl_easy_setopt(WRITEFUNCTION): %s",
				curlerrstr(code));
		free(url);
		fclose(f);
		free(filepath);
		return -1;
	}

	if (opts.flags & OPT_SHOW_PROGRESS)
		msg("Downloading content %08" PRIx32 "...",
				ds->content->contentid);

	/* Restoring download state from file relies on the order of downloading
	 * being deterministic and no downloads being done in parallel.
	 *
	 * Else, this would require a separate loop inside download_contents.
	 */
	if (opts.flags & OPT_RESUME) {
		switch (read_partial_file_into_state(ds)) {
		/* Download already complete */
		case 1:
			free(filepath);
			return 0;

		/* File partially downloaded; state has been read
		 * successfully.
		 */
		case 0:
			break;

		/* Some operation failed. */
		default:
			free(filepath);
			return -1;
		}
	}

	*errbuf = '\0';

	if ((code = curl_easy_perform(curl)) != CURLE_OK) {
		err("curl_easy_perform(%08" PRIx32 "): %s",
				ds->content->contentid, curlerrstr(code));
		free(url);
		fclose(f);
		free(filepath);
		return -1;
	}

	free(url);

	/* The number of bytes to resume from persists between individual
	 * URLs; we need to reset it to 0 after a completed transfer.
	 */
	if ((code = curl_easy_setopt(curl, CURLOPT_RESUME_FROM, 0))
			!= CURLE_OK) {
		err("curl_easy_setopt(URL:%08" PRIx32 "): %s",
				ds->content->contentid, curlerrstr(code));
		free(filepath);
		return -1;
	}

	fclose(f);

	if (util_get_file_size(filepath, &filelen) == 0
			&& filelen != ds->content->size) {
		err("Warning: File size mismatch (got %" PRIu64
				" vs. expected %" PRIu64
				") for content %08" PRIx32,
				filelen,
				ds->content->size,
				ds->content->contentid);
	}

	if (ds->flags & DS_ERROR) {
		free(filepath);
		return -1;
	}

	if (!(opts.flags & OPT_HAS_KEY)) {
		free(filepath);
		return 0;
	}

	/* TMD SHA-1/hash tree-based verification happened as part of the
	 * decryption for blockwise crypto contents.
	 */
	if (has_simple_crypto(ds->content)) {
		gcry_md_final(ds->hasher);

		if (memcmp(gcry_md_read(ds->hasher, ds->content->hashalgo),
					ds->content->hash,
					gcry_md_get_algo_dlen(ds->content->hashalgo))
				!= 0) {
			err("Error: Hash mismatch for content %08" PRIx32,
					ds->content->contentid);
			free(filepath);
			return -1;
		}
	}

	gcry_cipher_reset(ds->cipher);
	gcry_md_reset(ds->hasher);

	free(filepath);
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

		if ((ret = download_content(&ds)) != 0)
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

	/* The -r option does *not* prevent redownloading tmd/cetk. Those are
	 * small enough to fetch anew.
	 */

	if ((ret = download_tmd()) != 0)
		return ret;

	if ((opts.flags & OPT_DECRYPT_FROM_CETK)
			|| (opts.flags & OPT_KEEP_META)) {
		if ((ret = download_cetk()) != 0)
			return ret;
	}

	if (opts.flags & OPT_DECRYPT_FROM_CETK) {
		if ((ret = parse_cetk()) != 0)
			return -1;
	}

	if (opts.flags & OPT_KEEP_META) {
		if ((ret = write_file_from_memory("tmd", tmd, tmdsize)) != 0)
			return ret;

		if ((ret = write_file_from_memory("cetk", cetk, cetksize)) != 0)
			return ret;
	}

	if (opts.flags & OPT_KEY_ENCRYPTED) {
		if ((ret = decrypt_titlekey()) != 0)
			return ret;
	}

	if ((ret = download_contents()) != 0)
		return ret;

	download_fini();

	return 0;
}

