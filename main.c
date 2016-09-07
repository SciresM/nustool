#include <stdlib.h>

#include "crypto.h"
#include "main.h"
#include "download.h"
#include "types.h"
#include "util.h"

struct Options opts;

int main(int argc, char *argv[])
{
	errno_t ret;

	if (gcry_check_version("1.5.0") == NULL) {
		err("Your libgcrypt is too old. Required version: >= 1.5.0");
		return EXIT_FAILURE;
	}

	/* We don't deal with sensitive keys here. */
	if (gcry_control(GCRYCTL_DISABLE_SECMEM, 0) != 0) {
		err("Unable to disable gcrypt paranoia.");
		return EXIT_FAILURE;
	}

	if (gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0) != 0) {
		err("Unable to finish gcrypt initialization.");
		return EXIT_FAILURE;
	}

	if ((ret = util_parse_options(argc, argv)) != 0)
		return (ret < 0) ? EXIT_FAILURE : EXIT_SUCCESS;

	if (download_title() != 0)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

