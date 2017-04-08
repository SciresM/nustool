#include <string.h>

#include "crypto.h"
#include "types.h"

static void rotl(byte *buf)
{
	byte carry = 0;
	size_t i = 16;
	bool set_carry;

	do {
		set_carry = (buf[i - 1] & 0x80);

		buf[i - 1] = (byte)(buf[i - 1] << 1) | carry;

		if (set_carry)
			carry = 1;
		else
			carry = 0;
	} while (--i > 0);

	buf[15] |= carry;
}

static void rotl128(byte *buf, size_t bits)
{
	do {
		rotl(buf);
	} while (--bits > 0);
}

static void xor128(byte *out, const byte *a, const byte *b)
{
	for (size_t i = 0; i < 16; ++i)
		out[i] = a[i] ^ b[i];
}

static void add128(byte *out, const byte *a, const byte *b)
{
	byte carry = 0;
	size_t i = 16;

	do {
		out[i - 1] = a[i - 1] + b[i - 1] + carry;
		carry = (out[i - 1] < a[i - 1]);
	} while (--i > 0);
}

void *crypto_ctr_key_scramble(void *out, const void *keyX, const void *keyY)
{
	static const byte c[16] = {
		0x1F, 0xF9, 0xE9, 0xAA, 0xC5, 0xFE, 0x04, 0x08,
		0x02, 0x45, 0x91, 0xDC, 0x5D, 0x52, 0x76, 0x8A
	};
	byte x[16];
	byte y[16];

	memcpy(x, keyX, sizeof(x));
	memcpy(y, keyY, sizeof(y));

	rotl128(x, 2);
	xor128(out, x, y);
	memcpy(x, out, sizeof(x));
	add128(out, x, c);
	rotl128(out, 87);

	return out;
}

