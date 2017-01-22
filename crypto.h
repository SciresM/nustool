#ifndef NUSTOOL_CRYPTO_H
#define NUSTOOL_CRYPTO_H

#define GCRYPT_NO_DEPRECATED
#include <gcrypt.h>

void *crypto_ctr_key_scramble(void *out, const void *keyX, const void *keyY);

#endif

