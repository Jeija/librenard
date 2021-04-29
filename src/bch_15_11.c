#include <inttypes.h>
#include <stdbool.h>

#include "bch_15_11.h"

const uint16_t bch_15_11_generatormatrix[] = {
	0x6400, // 110010000000000
	0x3200, // 011001000000000
	0x1900, // 001100100000000
	0x6880, // 110100010000000
	0x5040, // 101000001000000
	0x2820, // 010100000100000
	0x7010, // 111000000010000
	0x3808, // 011100000001000
	0x7804, // 111100000000100
	0x5802, // 101100000000010
	0x4801  // 100100000000001
};

const uint16_t bch_15_11_paritycheckmatrix[] = {
	0x44d7, // 100010011010111
	0x26bc, // 010011010111100
	0x135e, // 001001101011110
	0x09af  // 000100110101111
};

const uint16_t bch_15_11_syndrometable[] = {
	0x0000, // 000000000000000, syndrome: 0000
	0x0800, // 000100000000000, syndrome: 0001
	0x1000, // 001000000000000, syndrome: 0010
	0x0100, // 000000100000000, syndrome: 0011
	0x2000, // 010000000000000, syndrome: 0100
	0x0020, // 000000000100000, syndrome: 0101
	0x0200, // 000001000000000, syndrome: 0110
	0x0008, // 000000000001000, syndrome: 0111
	0x4000, // 100000000000000, syndrome: 1000
	0x0001, // 000000000000001, syndrome: 1001
	0x0040, // 000000001000000, syndrome: 1010
	0x0002, // 000000000000010, syndrome: 1011
	0x0400, // 000010000000000, syndrome: 1100
	0x0080, // 000000010000000, syndrome: 1101
	0x0010, // 000000000010000, syndrome: 1110
	0x0004  // 000000000000100, syndrome: 1111
};

bool get_parity(uint16_t x) {
	x ^= x >> 8;
	x ^= x >> 4;
	x ^= x >> 2;
	x ^= x >> 1;
	return x & 1;
}

uint8_t bch_15_11_get_syndrome(uint16_t codeword) {
	uint8_t syndrome = 0x00;
	for (uint8_t i = 0; i < 4; ++i)
		syndrome |= get_parity(codeword & bch_15_11_paritycheckmatrix[i]) << (3 - i);
	return syndrome;
}

// Returns "closest" (by hamming distance) valid codeword
uint16_t bch_15_11_correct(uint16_t codeword, bool *changed) {
	uint8_t syndrome = bch_15_11_get_syndrome(codeword);
	*changed = syndrome != 0 ? true : false;
	return codeword ^ bch_15_11_syndrometable[syndrome];
}

// Returns 15-bit codeword for 11-bit message value
uint16_t bch_15_11_extend(uint16_t message) {
	uint16_t codeword = 0x0000;

	for (uint8_t i = 0; i < 11; ++i)
		if (message & (1 << i))
			codeword ^= bch_15_11_generatormatrix[10 - i];

	return codeword;
}
