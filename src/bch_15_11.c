#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

#include "bch_15_11.h"

const uint16_t bch_15_11_generatormatrix[] = {
	0b110010000000000,
	0b011001000000000,
	0b001100100000000,
	0b110100010000000,
	0b101000001000000,
	0b010100000100000,
	0b111000000010000,
	0b011100000001000,
	0b111100000000100,
	0b101100000000010,
	0b100100000000001
};

const uint16_t bch_15_11_paritycheckmatrix[] = {
	0b100010011010111,
	0b010011010111100,
	0b001001101011110,
	0b000100110101111
};

const uint16_t bch_15_11_syndrometable[] = {
	0b000000000000000, // syndrome: 0000
	0b000100000000000, // syndrome: 0001
	0b001000000000000, // syndrome: 0010
	0b000000100000000, // syndrome: 0011
	0b010000000000000, // syndrome: 0100
	0b000000000100000, // syndrome: 0101
	0b000001000000000, // syndrome: 0110
	0b000000000001000, // syndrome: 0111
	0b100000000000000, // syndrome: 1000
	0b000000000000001, // syndrome: 1001
	0b000000001000000, // syndrome: 1010
	0b000000000000010, // syndrome: 1011
	0b000010000000000, // syndrome: 1100
	0b000000010000000, // syndrome: 1101
	0b000000000010000, // syndrome: 1110
	0b000000000000100  // syndrome: 1111
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
