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
static inline void flip_bit(uint8_t *arg, uint32_t b)
{
	arg[b >> 3] ^= (128 >> (b & 7));
}

// Change the endianness of a 32-bit value.
static inline uint16_t swap_16(uint16_t val)
{
	return (val >> 8) | (val << 8);
}

// Change the endianness of a 32-bit value.
static inline uint32_t swap_32(uint32_t val)
{
	return ((val >> 24) & 0xff) | ((val << 8) & 0xff0000) | ((val >> 8) & 0xff00) | ((val << 24) & 0xff000000);
}

/* Checks if the xor of a value in the buffer and a random number
 * can be produced by a simple (bit/byte)flip. This function is
 * used as a check before more resource-intensive tasks are run.
 *
 * In particular, note that for a particular bit, a bit flip
 * will always result in an xor of 1.
 */
static bool is_bit_byte_flip(uint32_t xor)
{
	uint32_t buf = 0;

	// Trivial case (a^a = 0).
	if (!xor)
		return true;

	// Shift the xor'd value until the lsb is set.
	while ((xor & 1) == false) {
		buf++;
		xor >>= 1;
	}

	/* 0b1, 0b11 and 0b1111 are always good, since we're
	 * using 1-3 walking bits.
	 */
	if (xor == 0b1 || xor == 0b11 || xor == 0b1111)
		return 1;

	/* Now we're checking walking byte flips. Since we're doing
	 * byte, word and dword flips, only multiples of 8 are good.
	 * Cases where the position of the first 1 is not aligned
	 * cannot be produced by walking byte flips.
	 */
	if (buf & 7)
		return 0;

	/* If the stepover is good, (2^8)-1, (2^16)-1 & (2^32)-1
	 * are always good.
	 */
	if (xor == 0xff || xor == 0xffff || xor == 0xffffffff)
		return 1;

	return 0;
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

	for (int32_t cur = 0; cur < len - 1; cur++) {
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

	for (int32_t cur = 0; cur < len - 3; cur++) {
		*(uint32_t*)(buf + cur) ^= 0xFFFFFFFF;
		pprintf(buf);
		*(uint32_t*)(buf + cur) ^= 0xFFFFFFFF;
	}
	return true;
}

/* Set every byte in the input to one of the
 * 8-bit values that are deemed to be "interesting".
 */
static bool interesting_8(char *buf, int32_t len)
{
	static int8_t values[] = { -128, -1, 0, 1, 16, 32, 64, 100, 127 };
	uint8_t orig_val = 0;

	for (int32_t cur = 0; cur < len; cur++) {
		orig_val = buf[cur];

		for (int32_t i = 0; i < sizeof(values); i++) {
			buf[cur] = values[i];
			pprintf(buf);
			buf[cur] = orig_val;
		}
	}
	return true;
}

/* Set every word in the input to one of the
 * 16-bit values that are deemed to be "interesting".
 */
static bool interesting_16(char *buf, int32_t len)
{
	static int16_t values[] = { -128, -1, 0, 1, 16, 32, 64, 100, 127,
								-32768, -129, 128, 255, 256, 512, 1000,
								1024, 4096, 32767 };
	uint16_t orig_val = 0;

	if (len < 2)
		return false;

	for (int32_t cur = 0; cur < len - 1; cur++) {
		orig_val = *(uint16_t*)(buf + cur);

		for (int32_t i = 0; i < sizeof(values) / sizeof(int16_t); i++) {
			*(uint16_t*)(buf + cur) = values[i];
			pprintf(buf);

			// Change endianness and try again.
			*(uint16_t*)(buf + cur) = swap_16(values[i]);
			pprintf(buf);
		}

		*(uint16_t*)(buf + cur) = orig_val;
	}
	return true;
}

/* Set every long in the input to one of the
 * 32-bit values that are deemed to be "interesting".
 */
static bool interesting_32(char *buf, int32_t len)
{
	static int32_t values[] = { -128, -1, 0, 1, 16, 32, 64, 100, 127,
								-32768, -129, 128, 255, 256, 512, 1000,
								1024, 4096, 32767, -2147483648LL,
								-100663046, -32769, 32768, 65535, 65536,
								100663045, 2147483647 };
	uint32_t orig_val = 0;

	if (len < 4)
		return false;

	for (int32_t cur = 0; cur < len - 3; cur++) {
		orig_val = *(uint32_t*)(buf + cur);

		for (int32_t i = 0; i < sizeof(values) / sizeof(int16_t); i++) {
			*(uint32_t*)(buf + cur) = values[i];
			pprintf(buf);

			// Change endianness and try again.
			*(uint32_t*)(buf + cur) = swap_32(values[i]);
			pprintf(buf);
		}

		*(uint32_t*)(buf + cur) = orig_val;
	}
	return true;
}

// Add/subtract MAX_ARITH_VAL to/from each byte in the buffer.
static bool arithm_8(char *buf, int32_t len)
{
	uint32_t orig_val = 0;

	for (int32_t cur = 0; cur < len; cur++) {
		orig_val = buf[cur];

		for (int32_t i = 1; i <= MAX_ARITH_VAL; i++) {
			if (!is_bit_byte_flip(orig_val ^ (orig_val + i))) {
				buf[cur] = orig_val + i;
				pprintf(buf);
			}

			if (!is_bit_byte_flip(orig_val ^ (orig_val - i))) {
				buf[cur] = orig_val - i;
				pprintf(buf);
			}

			buf[cur] = orig_val;
		}
	}
	return true;
}

// Add/subtract 1...MAX_ARITH_VAL to/from each word in the buffer.
static bool arithm_16(char *buf, int32_t len)
{
	uint16_t orig_val = 0;

	for (int32_t cur = 0; cur < len - 1; cur++) {
		orig_val = *(uint16_t*)(buf + cur);

		for (int32_t i = 1; i <= MAX_ARITH_VAL; i++) {
			/* Skip this step if the operation doesn't overflow
			 * (produce values that are greater than 0xff).
			 * Also check if the operation could be replaced by a
			 * bit/byte flip, and skip if it can.
			 */
			if ((orig_val & 0xff) + i > 0xff && !is_bit_byte_flip(orig_val ^ (orig_val + i))) {
				*(uint16_t*)(buf + cur) = orig_val + i;
				pprintf(buf);
			}

			// Same thing goes for subtraction.
			if ((orig_val & 0xff) + i < 0 && !is_bit_byte_flip(orig_val ^ (orig_val - i))) {
				*(uint16_t*)(buf + cur) = orig_val - i;
				pprintf(buf);
			}

			// Do it in big endian mode too (addition).
			if ((orig_val >> 8) + i > 0xff && !is_bit_byte_flip(orig_val ^ swap_16(swap_16(orig_val) + i))) {
				*(uint16_t*)(buf + cur) = swap_16(swap_16(orig_val) + i);
				pprintf(buf);
			}

			// Big endian subtraction.
			if ((orig_val >> 8) + i < 0 && !is_bit_byte_flip(orig_val ^ swap_16(swap_16(orig_val) - i))) {
				*(uint16_t*)(buf + cur) = swap_16(swap_16(orig_val) - i);
				pprintf(buf);
			}

			*(uint16_t*)(buf + i) = orig_val;
		}
	}
	return true;
}

// Add/subtract 1...MAX_ARITH_VAL to/from each dword in the buffer.
static bool arithm_32(char *buf, int32_t len)
{
	uint32_t orig_val = 0;

	for (int32_t cur = 0; cur < len - 1; cur++) {
		orig_val = *(uint32_t*)(buf + cur);

		for (int32_t i = 1; i <= MAX_ARITH_VAL; i++) {
			/* Skip this step if the operation doesn't overflow
			* (produce values that are greater than 0xffff).
			* Also check if the operation could be replaced by a
			* bit/byte flip, and skip if it can.
			*/
			if ((orig_val & 0xffff) + i > 0xffff && !is_bit_byte_flip(orig_val ^ (orig_val + i))) {
				*(uint32_t*)(buf + cur) = orig_val + i;
				pprintf(buf);
			}

			// Same thing goes for subtraction.
			if ((orig_val & 0xff) + i < 0 && !is_bit_byte_flip(orig_val ^ (orig_val - i))) {
				*(uint32_t*)(buf + cur) = orig_val - i;
				pprintf(buf);
			}

			// Do it in big endian mode too (addition).
			if ((swap_32(orig_val) & 0xffff) + i > 0xffff && !is_bit_byte_flip(orig_val ^ swap_32(swap_32(orig_val) + i))) {
				*(uint32_t*)(buf + cur) = swap_32(swap_32(orig_val) + i);
				pprintf(buf);
			}

			// Big endian subtraction.
			if ((swap_32(orig_val) & 0xffff) + i < 0 && !is_bit_byte_flip(orig_val ^ swap_32(swap_32(orig_val) - i))) {
				*(uint32_t*)(buf + cur) = swap_32(swap_32(orig_val) - i);
				pprintf(buf);
			}

			*(uint32_t*)(buf + i) = orig_val;
		}
	}
	return true;
}

bool fuzz_mutate(char *buf, int32_t len)
{
	// This will use the helper functions in this file
	// to create deterministic and random test cases.
	return true;
}