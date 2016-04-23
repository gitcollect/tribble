#include "tribble-srv.hpp"

/* This function flips a single bit in a piece of data. For reference:
 * (b >> 3) is 0 in [0-7], 1 in [8-15], etc..
 * (b & 7) is [0-7] in [0-7], [0-7] in [8-15], etc...
 * so (128 >> (b&7)) is (128 >> [0-7]),
 * which basically generates every power of 2 between 1 and 128, in reverse
 * order (128, 128/2, 128/4, ... 1).
 *
 * Thus, as b grows, the function goes through the first byte, flipping the
 * msb, then msb-1, ..., then it switches to the second byte, etc., until
 * b == len << 3.
 */
static void flip_bit(uint8_t *arg, uint32_t b)
{
	arg[b >> 3] ^= (128 >> (b & 7));
}


/* Go through the whole buffer and use n
 * "walking" bitflips (msb->lsb).
 */
static bool bitflip_n(char *buf, int32_t len, uint32_t num_bits)
{
	int32_t max = (len << 3) - (num_bits-1);

	for (int32_t cur = 0; cur < max; cur++) {
		for (uint32_t step = 0; step < num_bits; step++)
			flip_bit((uint8_t*)buf, cur + step);

		pprintf(buf);

		for (uint32_t step = 0; step < num_bits; step++)
			flip_bit((uint8_t*)buf, cur + step);
	}
	return true;
}

// Go through the whole buffer and flip every byte.
static bool byteflip_8(char *buf, int32_t len)
{
	if (len < 1)
		return false;

	for (int32_t cur = 0; cur < len; cur++) {
		buf[cur] ^= 0xFF;
		pprintf(buf);
		buf[cur] ^= 0xFF;
	}
	return true;
}

// Go through the whole buffer and flip two-byte chunks.
static bool byteflip_16(char *buf, int32_t len)
{
	if (len < 2)
		return false;

	for (int32_t cur = 0; cur < len-1; cur++) {
		*(uint16_t*)(buf + cur) ^= 0xFFFF;
		pprintf(buf);
		*(uint16_t*)(buf + cur) ^= 0xFFFF;
	}
	return true;
}

// Go through the whole buffer and flip four-byte chunks.
static bool byteflip_32(char *buf, int32_t len)
{
	if (len < 4)
		return false;

	for (int32_t cur = 0; cur < len - 1; cur++) {
		*(uint32_t*)(buf + cur) ^= 0xFFFFFFFF;
		pprintf(buf);
		*(uint32_t*)(buf + cur) ^= 0xFFFFFFFF;
	}
	return true;
}

bool fuzz_mutate(char *buf, int32_t len)
{
	// This will use the helper functions in this file
	// to create deterministic and random test cases.

	return true;
}