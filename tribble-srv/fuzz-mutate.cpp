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
	 * using 1, 2 & 4 walking bits.
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

/* Checks if old_val can be transformed into new_val by the arithmetic
 * step of the fuzzer.
 */
static bool is_arith(uint32_t old_val, uint32_t new_val, uint8_t len)
{
	uint32_t oldv = 0, newv = 0, diffs = 0;
	uint32_t val1 = 0, val2 = 0;

	// Trivial case.
	if (old_val == new_val)
		return 1;

	/* Go through every single byte and check if there is
	 * a difference that's indicative of a possible arithmetic
	 * operation.
	 */
	for (int32_t i = 0; i < len; i++) {
		val1 = old_val >> (8 * i);
		val2 = new_val >> (8 * i);

		if (val1 != val2) {
			diffs++;
			oldv = val1;
			newv = val2;
		}
	}

	/* If there's only a one-byte difference btw. the two values,
	 * this could possibly be an arithmetic operation, but only if
	 * the range is good.
	 */
	if (diffs == 1)
		if ((uint8_t)(oldv - newv) <= MAX_ARITH_VAL || (uint8_t)(newv - oldv) <= MAX_ARITH_VAL)
			return 1;

	// No other 1-byte case is good.
	if (len == 1)
		return 0;

	// Do the same thing with words.
	diffs = 0;

	for (int32_t i = 0; i < len / 2; i++) {
		val1 = old_val >> (16 * i),
		val2 = new_val >> (16 * i);

		if (val1 != val2) {
			diffs++;
			oldv = val1;
			newv = val2;
		}
	}

	/* If there's only a two-byte difference btw. the two values,
	* this could possibly be an arithmetic operation, but only if
	* the range is good.
	*/
	if (diffs == 1) {
		if ((uint16_t)(oldv - newv) <= MAX_ARITH_VAL || (uint16_t)(newv - oldv) <= MAX_ARITH_VAL)
			return 1;

		// Big endian mode.
		oldv = swap_16(oldv);
		newv = swap_16(newv);

		if ((uint16_t)(oldv - newv) <= MAX_ARITH_VAL || (uint16_t)(newv - oldv) <= MAX_ARITH_VAL)
			return 1;
	}

	// Same thing goes for dwords. No need to shift bits, obviously.
	if (len == 4) {
		if ((uint32_t)(old_val - new_val) <= MAX_ARITH_VAL || (uint32_t)(new_val - old_val) <= MAX_ARITH_VAL)
			return 1;

		// Big endian mode.
		new_val = swap_32(new_val);
		old_val = swap_32(old_val);

		if ((uint32_t)(old_val - new_val) <= MAX_ARITH_VAL || (uint32_t)(new_val - old_val) <= MAX_ARITH_VAL)
			return 1;
	}

	return 0;
}

static bool is_interest(uint32_t old_val, uint32_t new_val, uint8_t len, uint8_t check_le)
{
	static int8_t values_8[] = { -128, -1, 0, 1, 16, 32, 64, 100, 127 };
	static int16_t values_16[] = { -128, -1, 0, 1, 16, 32, 64, 100, 127, -32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767 };
	static int32_t values_32[] = { -128, -1, 0, 1, 16, 32, 64, 100, 127, -32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767, -2147483648LL, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647 };

	uint32_t val = 0;

	// Trivial case.
	if (old_val == new_val)
		return 1;

	// Byte case.
	for (int32_t i = 0; i < len; i++) {
		for (int32_t j = 0; j < sizeof(values_8); j++) {
			val = (old_val & ~(0xff << (i * 8))) | (((uint8_t)values_8[j]) << (i * 8));

			if (new_val == val)
				return 1;
		}
	}

	if (len == 2 && !check_le)
		return 0;

	// Word & dword case.
	for (int32_t i = 0; i < len - 1; i++) {
		for (int32_t j = 0; j < sizeof(values_16) / sizeof(uint16_t); j++) {

			val = (old_val & ~(0xffff << (i * 8))) | (((uint16_t)values_16[j]) << (i * 8));

			if (new_val == val)
				return 1;

			if (len > 2) {
				val = (old_val & ~(0xffff << (i * 8))) | (swap_16(values_16[j]) << (i * 8));

				if (new_val == val)
					return 1;
			}
		}
	}

	// Dword case.
	if (len == 4 && check_le) {
		for (int32_t i = 0; i < sizeof(values_32) / sizeof(uint32_t); i++) {
			if (new_val == (uint32_t)values_32[i])
				return 1;
		}
	}

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
			if (is_bit_byte_flip(orig_val ^ (uint8_t)values[i]) || is_arith(orig_val, (uint8_t)values[i], 1))
				continue;

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
	static int16_t values[] = { -128, -1, 0, 1, 16, 32, 64, 100, 127, -32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767 };
	uint16_t orig_val = 0;

	if (len < 2)
		return false;

	for (int32_t cur = 0; cur < len - 1; cur++) {
		orig_val = *(uint16_t*)(buf + cur);

		for (int32_t i = 0; i < sizeof(values) / sizeof(int16_t); i++) {
			if (is_bit_byte_flip(orig_val ^ (uint16_t)values[i])
				|| is_arith(orig_val, (uint16_t)values[i], 2)
				|| is_interest(orig_val, (uint16_t)values[i], 2, 0))
				continue;

			*(uint16_t*)(buf + cur) = values[i];
			pprintf(buf);

			/* Change endianness and try again. Don't do this
			 * in cases where the endianness doesn't matter.
			 */
			if ((uint16_t)values[i] == swap_16(values[i])
				|| is_bit_byte_flip(orig_val ^ swap_16(values[i]))
				|| is_arith(orig_val, swap_16(values[i]), 2)
				|| is_interest(orig_val, swap_16(values[i]), 2, 1))
				continue;

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
	static int32_t values[] = { -128, -1, 0, 1, 16, 32, 64, 100, 127, -32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767, -2147483648LL, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647 };
	uint32_t orig_val = 0;

	if (len < 4)
		return false;

	for (int32_t cur = 0; cur < len - 3; cur++) {
		orig_val = *(uint32_t*)(buf + cur);

		for (int32_t i = 0; i < sizeof(values) / sizeof(int16_t); i++) {
			if (is_bit_byte_flip(orig_val ^ (uint32_t)values[i])
				|| is_arith(orig_val, (uint32_t)values[i], 4)
				|| is_interest(orig_val, (uint32_t)values[i], 4, 0))
				continue;

			*(uint32_t*)(buf + cur) = values[i];
			pprintf(buf);

			/* Change endianness and try again. Don't do this
			 * in cases where the endianness doesn't matter.
			 */
			if ((uint32_t)values[i] == swap_32(values[i])
				|| is_bit_byte_flip(orig_val ^ swap_32(values[i]))
				|| is_arith(orig_val, swap_32(values[i]), 4)
				|| is_interest(orig_val, swap_32(values[i]), 4, 1))
				continue;

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

			*(uint16_t*)(buf + cur) = orig_val;
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

			*(uint32_t*)(buf + cur) = orig_val;
		}
	}
	return true;
}

bool fuzz_mutate(char *buf, int32_t len)
{
	pprintf("bitflip 1");
	bitflip_n(buf, len, 1);
	pprintf("bitflip 2");
	bitflip_n(buf, len, 2);
	pprintf("bitflip 4");
	bitflip_n(buf, len, 4);
	pprintf("arithm 8");
	arithm_8(buf, len);
	pprintf("arithm 16");
	arithm_16(buf, len);
	pprintf("arithm 32");
	arithm_32(buf, len);
	pprintf("int 8");
	interesting_8(buf, len);
	pprintf("int 16");
	interesting_16(buf, len);
	pprintf("int 32");
	interesting_32(buf, len);
	return true;
}