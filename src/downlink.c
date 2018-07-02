#include <string.h>
#include <stdio.h>

#include "sigfox_hmac.h"
#include "sigfox_crc.h"
#include "bch_15_11.h"
#include "downlink.h"
#include "common.h"

uint8_t SFX_DL_PREAMBLE[] = {
	0x2a, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xb2, 0x27
};

/*
 * Scrambling using 9-bit Linear-feedback shift register
 * 
 * https://en.wikipedia.org/wiki/Linear-feedback_shift_register
 * Polynomial: x^9 + x^4 + 1
 */
void LFSR(uint16_t *state)
{
	for (uint8_t i = 0; i < 8; ++i) {
		bool tapA = (*state & (1 << 5)) ? true : false; // tap for x^4
		bool tapB = (*state & (1 << 0)) ? true : false; // tap for x^9

		*state = (tapA ^ tapB ? 0x100 : 0) | (*state >> 1);
	}
}

uint32_t extractLowerBits(uint32_t value, uint8_t bitcount)
{
	return ((1 << bitcount) - 1) & value;
}

void sfx_downlink_payload_scramble(uint8_t *payloadbuf, sfx_commoninfo common) {
	/*
	 * Initialize LFSR with seed value derived from device ID and uplink SN (for descrambling)
	 */
	uint32_t devid_seed = common.devid & 0xff00ffff;
	uint16_t state = (common.seqnum * devid_seed) & 0x1ff;

	if (state == 0)
		state = 0x1ff;

	/*
	 * Descramble message by XORing 9-bit LFSR content with coded payload
	 */
	for (uint8_t j = 0; j < 8; ++j) {
		LFSR(&state);

		payloadbuf[j    ] = payloadbuf[j    ] ^ (state >> (j + 1));
		payloadbuf[j + 1] = payloadbuf[j + 1] ^ (extractLowerBits(state, j + 1) << (7 - j));
	}

	for (uint8_t j = 0; j < 6; ++j) {
		LFSR(&state);

		payloadbuf[j + 9] = payloadbuf[j + 9] ^ (state >> (j + 1));

		if (j != 5)
			payloadbuf[j + 10] = payloadbuf[j + 10] ^ (extractLowerBits(state, j + 1) << (7 - j));
	}
}

/*
 * HMAC calculation
 * AES function input consists of device id, plain message and uplink sequence number
 */
uint16_t sfx_downlink_get_hmac(uint8_t *message, sfx_commoninfo common) {
	uint8_t encrypted_data[32];
	uint8_t data_to_encrypt[32];
	data_to_encrypt[0] = (common.devid & 0x000000ff) >> 0;
	data_to_encrypt[1] = (common.devid & 0x0000ff00) >> 8;
	data_to_encrypt[2] = (common.devid & 0x00ff0000) >> 16;
	data_to_encrypt[3] = (common.devid & 0xff000000) >> 24;
	data_to_encrypt[4] = (common.seqnum & 0x00ff) >> 0;
	data_to_encrypt[5] = (common.seqnum & 0xff00) >> 8;
	memcpy(&data_to_encrypt[6], message, SFX_DL_MSGLEN);
	data_to_encrypt[14] = (common.devid & 0x000000ff) >> 0;
	data_to_encrypt[15] = (common.devid & 0x0000ff00) >> 8;

	aes_128_cbc_encrypt(encrypted_data, data_to_encrypt, 16, common.key);

	return (encrypted_data[0] << 8) | encrypted_data[1];
}

void sfx_downlink_decode(sfx_dl_encoded encoded, sfx_commoninfo common, sfx_dl_plain *decoded)
{
	decoded->crc_ok = false;
	decoded->hmac_ok = false;

	/*
	 * Descramble payload (scrambler / descrambler are identical)
	 */
	uint8_t payload[SFX_DL_PAYLOADLEN];
	memcpy(payload, encoded.payload, sizeof(payload));
	sfx_downlink_payload_scramble(payload, common);

	/*
	 * FEC and "deinterleaving"
	 * The downlink uses a BCH(15,11,1)-code where the n-th bit of every payload byte is part of
	 * the code word (some sort of interleaving). The code is systematic in the way that bytes
	 * 0-3 contain just redundancy information and bytes 4-14 contain the actual message (and thus
	 * bits 0-3 are for reduandancy while bits 4-14 contain data).
	 */
	for (uint8_t bitoffset = 0; bitoffset < 8; ++bitoffset) {
		uint16_t code = 0x0000;

		// "deinterleave": combine bits from payload bytes to single codeword
		for (uint8_t byte = 0; byte < 15; ++byte)
			code |= ((payload[byte] & (1 << (7 - bitoffset))) ? 1 : 0) << (14 - byte);

		code = bch_15_11_correct(code);

		// "interleave": write back bits to payload bytes
		for (uint8_t byte = 0; byte < 15; ++byte) {
			if (code & (1 << (14 - byte)))
				payload[byte] |= 1 << (7 - bitoffset);
			else
				payload[byte] &= ~(1 << (7 - bitoffset));
		}
	}

	/*
	 * Extract message
	 */
	memcpy(decoded->msg, &payload[SFX_DL_MSGOFFSET], SFX_DL_MSGLEN);

	/*
	 * Check message CRC
	 */
	uint8_t crc8 = SIGFOX_CRC_crc8(&payload[SFX_DL_MSGOFFSET], SFX_DL_MSGLEN + SFX_DL_HMACLEN);
	decoded->crc_ok = (crc8 == payload[SFX_DL_CRCOFFSET]);

	/*
	 * Check message HMAC
	 */
	uint16_t hmac = sfx_downlink_get_hmac(decoded->msg, common);
	decoded->hmac_ok = ((hmac & 0xff00) >> 8 == payload[SFX_DL_HMACOFFSET] && (hmac & 0xff) == payload[SFX_DL_HMACOFFSET + 1]);
}

void sfx_downlink_encode(sfx_dl_plain to_encode, sfx_commoninfo common, sfx_dl_encoded *encoded)
{
	/*
	 * Calculate message HMAC
	 */
	uint16_t hmac = sfx_downlink_get_hmac(to_encode.msg, common);
	encoded->payload[SFX_DL_HMACOFFSET] = (hmac & 0xff00) >> 8;
	encoded->payload[SFX_DL_HMACOFFSET + 1] = hmac & 0xff;

	/*
	 * Copy raw (no FEC, unscrambled) message to frame payload for CRC calculation
	 */
	memcpy(&encoded->payload[SFX_DL_MSGOFFSET], to_encode.msg, SFX_DL_MSGLEN);

	/*
	 * Calculate message CRC
	 * CRC is calculated for buffer comprised of message and HMAC
	 */
	uint8_t crc8 = SIGFOX_CRC_crc8(&encoded->payload[SFX_DL_MSGOFFSET], SFX_DL_MSGLEN + SFX_DL_HMACLEN);
	encoded->payload[SFX_DL_CRCOFFSET] = crc8;

	/*
	 * Add redundancy for FEC (and "interleaving")
	 */
	for (uint8_t bitoffset = 0; bitoffset < 8; ++bitoffset) {
		uint16_t code = 0x0000;

		// "deinterleave": combine bits from message bytes to single 11-bit message value
		for (uint8_t byte = 0; byte < 11; ++byte)
			if (encoded->payload[SFX_DL_MSGOFFSET + byte] & (1 << (7 - bitoffset)))
				code |= 1 << (10 - byte);

		code = bch_15_11_extend(code);

		// "interleave": write back bits to payload bytes
		for (uint8_t byte = 0; byte < 15; ++byte) {
			if (code & (1 << (14 - byte)))
				encoded->payload[byte] |= 1 << (7 - bitoffset);
			else
				encoded->payload[byte] &= ~(1 << (7 - bitoffset));
		}
	}

	/*
	 * Scramble payload (scrambler / descrambler are identical)
	 */
	sfx_downlink_payload_scramble(encoded->payload, common);
}
