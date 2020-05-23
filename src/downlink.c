#include <string.h>

#include "sigfox_mac.h"
#include "sigfox_crc.h"
#include "bch_15_11.h"
#include "downlink.h"
#include "common.h"

/**
 * @brief content of Sigfox's 13-byte (::SFX_DL_PREAMBLELEN) downlink preamble
 */
uint8_t SFX_DL_PREAMBLE[] = {
	0x2a, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xb2, 0x27
};

/*
 * Scrambling using 9-bit Linear-feedback shift register
 * 
 * https://en.wikipedia.org/wiki/Linear-feedback_shift_register
 * Polynomial: x^9 + x^5 + 1
 *
 * For detailed description of scrambling algorithm, see section 3.6 of Bachelor's Thesis
 * "Reverse Engineering of the Sigfox Radio Protocol and Implementation of an Alternative Sigfox Network Stack"
 */
void LFSR(uint16_t *state)
{
	for (uint8_t i = 0; i < 8; ++i) {
		bool tapA = (*state & (1 << 5)) ? true : false; // tap for x^5
		bool tapB = (*state & (1 << 0)) ? true : false; // tap for x^9

		*state = (tapA ^ tapB ? 0x100 : 0) | (*state >> 1);
	}
}

uint32_t extractLowerBits(uint32_t value, uint8_t bitcount)
{
	return ((1 << bitcount) - 1) & value;
}

void sfx_downlink_frame_scramble(uint8_t *payloadbuf, sfx_commoninfo common)
{
	/*
	 * Initialize LFSR with seed value derived from device ID and uplink SN (for descrambling)
	 */
	uint16_t state = (common.seqnum * common.devid) & 0x1ff;

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
 * MAC calculation
 * AES function input consists of device id, plain message and uplink sequence number
 * See section 3.3 of Bachelor's Thesis
 * "Reverse Engineering of the Sigfox Radio Protocol and Implementation of an Alternative Sigfox Network Stack"
 */
uint16_t sfx_downlink_get_mac(uint8_t *message, sfx_commoninfo common) {
	uint8_t encrypted_data[16];
	uint8_t data_to_encrypt[16];
	data_to_encrypt[0] = (common.devid & 0x000000ff) >> 0;
	data_to_encrypt[1] = (common.devid & 0x0000ff00) >> 8;
	data_to_encrypt[2] = (common.devid & 0x00ff0000) >> 16;
	data_to_encrypt[3] = (common.devid & 0xff000000) >> 24;
	data_to_encrypt[4] = (common.seqnum & 0x00ff) >> 0;
	data_to_encrypt[5] = (common.seqnum & 0xff00) >> 8;
	memcpy(&data_to_encrypt[6], message, SFX_DL_PAYLOADLEN);
	data_to_encrypt[14] = (common.devid & 0x000000ff) >> 0;
	data_to_encrypt[15] = (common.devid & 0x0000ff00) >> 8;

	renard_aes_128_cbc_encrypt(encrypted_data, data_to_encrypt, 16, common.key);

	return (encrypted_data[0] << 8) | encrypted_data[1];
}

/**
 * @brief retrieve contents of Sigfox downlink from given raw frame
 * @param to_decode the raw contents of the Sigfox downlink frame to decode
 * @param common General information about the Sigfox object and its state. If a wrong NAK is provided, sfx_dl_plain::mac_ok will be false, but decoding will still work.
 * @param decoded output, contents of Sigfox frame and whether MAC / CRC match
 * @attention This function applies Forward Error Correction (FEC). If FEC has occurred during decoding, sfx_dl_plain::fec_corrected will be set to true in the output.
 */
void sfx_downlink_decode(sfx_dl_encoded to_decode, sfx_commoninfo common, sfx_dl_plain *decoded)
{
	decoded->crc_ok = false;
	decoded->mac_ok = false;

	/*
	 * Descramble frame (scrambler / descrambler are identical)
	 */
	uint8_t frame[SFX_DL_FRAMELEN];
	memcpy(frame, to_decode.frame, sizeof(frame));
	sfx_downlink_frame_scramble(frame, common);

	/*
	 * FEC and "deinterleaving"
	 * The downlink uses a BCH(15,11,1)-code where the n-th bit of every frame byte is part of
	 * the code word (some sort of interleaving). The code is systematic in the way that bytes
	 * 0-3 contain just redundancy information and bytes 4-14 contain the actual message (and thus
	 * bits 0-3 are for reduandancy while bits 4-14 contain data).
	 * `fec_corrected` stores wheter there were any bit errors that were corrected by the BCH ECC. 
	 */
	decoded->fec_corrected = false;
	for (uint8_t bitoffset = 0; bitoffset < 8; ++bitoffset) {
		uint16_t code = 0x0000;

		// "deinterleave": combine bits from frame bytes to single codeword
		for (uint8_t byte = 0; byte < 15; ++byte)
			code |= ((frame[byte] & (1 << (7 - bitoffset))) ? 1 : 0) << (14 - byte);

		bool changed = false;
		code = bch_15_11_correct(code, &changed);
		if (changed)
			decoded->fec_corrected = true;

		// "interleave": write back bits to frame bytes
		for (uint8_t byte = 0; byte < 15; ++byte) {
			if (code & (1 << (14 - byte)))
				frame[byte] |= 1 << (7 - bitoffset);
			else
				frame[byte] &= ~(1 << (7 - bitoffset));
		}
	}

	/*
	 * Extract payload from frame
	 */
	memcpy(decoded->payload, &frame[SFX_DL_PAYLOADOFFSET], SFX_DL_PAYLOADLEN);

	/*
	 * Check CRC
	 */
	uint8_t crc8 = SIGFOX_CRC_crc8(&frame[SFX_DL_PAYLOADOFFSET], SFX_DL_PAYLOADLEN + SFX_DL_MACLEN);
	decoded->crc_ok = (crc8 == frame[SFX_DL_CRCOFFSET]);

	/*
	 * Check MAC
	 */
	uint16_t mac = sfx_downlink_get_mac(decoded->payload, common);
	decoded->mac_ok = ((mac & 0xff00) >> 8 == frame[SFX_DL_MACOFFSET] && (mac & 0xff) == frame[SFX_DL_MACOFFSET + 1]);
}

/**
 * @brief generate raw Sigfox downlink frame from given contents, for given Sigfox object and its state
 * @param to_encode content of raw Sigfox frame, only sfx_dl_plain::payload has to be set, all other members of ::sfx_dl_plain are ignored
 * @param common general information about the Sigfox object and its state
 * @param encoded output, raw Sigfox downlink frame, excluding preamble
 */
void sfx_downlink_encode(sfx_dl_plain to_encode, sfx_commoninfo common, sfx_dl_encoded *encoded)
{
	/*
	 * Calculate MAC
	 */
	uint16_t mac = sfx_downlink_get_mac(to_encode.payload, common);
	encoded->frame[SFX_DL_MACOFFSET] = (mac & 0xff00) >> 8;
	encoded->frame[SFX_DL_MACOFFSET + 1] = mac & 0xff;

	/*
	 * Copy raw (no FEC, unscrambled) payload to frame for CRC calculation
	 */
	memcpy(&encoded->frame[SFX_DL_PAYLOADOFFSET], to_encode.payload, SFX_DL_PAYLOADLEN);

	/*
	 * Calculate CRC
	 * CRC is calculated for buffer comprised of payload and MAC
	 */
	uint8_t crc8 = SIGFOX_CRC_crc8(&encoded->frame[SFX_DL_PAYLOADOFFSET], SFX_DL_PAYLOADLEN + SFX_DL_MACLEN);
	encoded->frame[SFX_DL_CRCOFFSET] = crc8;

	/*
	 * Add redundancy for FEC (and "interleaving")
	 */
	for (uint8_t bitoffset = 0; bitoffset < 8; ++bitoffset) {
		uint16_t code = 0x0000;

		// "deinterleave": combine bits from payload bytes to single 11-bit payload value
		for (uint8_t byte = 0; byte < 11; ++byte)
			if (encoded->frame[SFX_DL_PAYLOADOFFSET + byte] & (1 << (7 - bitoffset)))
				code |= 1 << (10 - byte);

		code = bch_15_11_extend(code);

		// "interleave": write back bits to frame bytes
		for (uint8_t byte = 0; byte < 15; ++byte) {
			if (code & (1 << (14 - byte)))
				encoded->frame[byte] |= 1 << (7 - bitoffset);
			else
				encoded->frame[byte] &= ~(1 << (7 - bitoffset));
		}
	}

	/*
	 * Scramble frame (scrambler / descrambler are identical)
	 */
	sfx_downlink_frame_scramble(encoded->frame, common);
}
