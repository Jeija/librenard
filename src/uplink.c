#include <stdio.h>

#include "sigfox_hmac.h"
#include "sigfox_crc.h"
#include "uplink.h"
#include "common.h"

void setnibble(uint8_t *buffer, uint8_t nibble, uint8_t value)
{
	value &= 0xf;
	uint8_t byte = nibble / 2;
	bool highnibble = (nibble % 2) == 0;

	if (highnibble)
		buffer[byte] = (buffer[byte] & 0x0f) | (value << 4);
	else
		buffer[byte] = (buffer[byte] & 0xf0) | value;
}

/*
 * Convolutional code encoder
 * The encoder looks at a maximum of 8 bits at a time, so the polynomial may not be of higher order
 */
void convcode(uint8_t *inbuffer, uint8_t *outbuffer, uint8_t length, uint8_t offset, uint8_t polynomial)
{
	uint8_t i;
	int8_t bit;
	uint8_t shiftregister = 0x00;

	for (i = offset; i < length; ++i) {
		for (bit = 7; bit >= 0; --bit) {
			bool in = (0x01 & (inbuffer[i] >> bit)) != 0;
			shiftregister = (shiftregister << 1) | (in ? 0x01 : 0x00);

			// Determine the output value of the filter with given polynomial for current bit
			// __builtin_popcount returns the hamming weight of its argument
			uint8_t convoluted = shiftregister & polynomial;
			bool out = __builtin_popcount(convoluted) % 2 == 1;
			outbuffer[i] = (outbuffer[i] & ~(1 << bit)) | ((out ? 1 : 0) << bit);
		}
	}
}

/*
 * Frametypes as used in the sigfox standard
 * These values were probably chosen to achieve a minimal
 * hamming distance of 5 so that 2 bit errors can be corrected.
 */
uint16_t frametypes[3][5] = {
	// 1bit  1Byte  4Byte  8Byte 12Byte
	{ 0x06b, 0x08d, 0x35f, 0x611, 0x94c }, // first transmission
	{ 0x6e0, 0x0d2, 0x598, 0x6bf, 0x971 }, // second transmission
	{ 0x034, 0x302, 0x5a3, 0x72c, 0x997 }  // third transmission
};

// TODO: fix nomenclaature ("payload")
void sfx_uplink_encode(sfx_ul_plain uplink, sfx_commoninfo common, sfx_ul_encoded *encoded)
{
	uint8_t i;
	uint8_t replica;

	// All replicas: Preamble and frame type
	for (replica = 0; replica < 3; ++replica) {
		// Preamble is 5 (= SFX_UL_PREAMBLELEN_NIBBLES) times 0b1010 = 0xa
		for (i = 0; i < SFX_UL_PREAMBLELEN_NIBBLES; ++i)
			setnibble(encoded->payload[replica], i, 0xa);

		// Frame type also defines message length, three cases:
		// * single bit
		// * 1 byte
		// * 4 / 8 / 12 bytes
		uint16_t ftype;
		if (uplink.singlebit)
			ftype = frametypes[replica][0];
		else if (uplink.msglen == 1)
			ftype = frametypes[replica][1];
		else
			ftype = frametypes[replica][(uplink.msglen - 1) / 4 + 2];

		setnibble(encoded->payload[replica], 5, (ftype & 0xf00) >> 8);
		setnibble(encoded->payload[replica], 6, (ftype & 0x0f0) >> 4);
		setnibble(encoded->payload[replica], 7, (ftype & 0x00f) >> 0);
	}

	// Construct payload: flags, sequence number, device ID, message
	uint8_t payload[SFX_UL_MAX_PAYLOADLEN];
	uint8_t flags = 0x0;
	uint8_t paddinglen = (12 - uplink.msglen) % 4;

	// Special case: Special frame format for single-byte messages, therefore
	// single-byte messages don't need padding
	if (uplink.msglen == 1)
		paddinglen = 0;

	// For single bit messages:
	// MSB of flag nibble is always 1, second bit is the message
	// content (true or false)
	if (uplink.singlebit)
		flags |= 0b1000 | ((uplink.msg[0] == 0) ? 0b0000 : 0b0100);

	// For multiple byte messages:
	// Upper two bits of flags define how many bytes in the message are
	// padded (with parts of the HMAC)
	else
		flags |= paddinglen << 2;

	// Set downlink bit in flags if requested
	if (uplink.request_downlink)
		flags |= 0b0010;

	setnibble(payload, 0, flags);
	setnibble(payload, 1, (common.seqnum & 0xf00) >> 8);
	setnibble(payload, 2, (common.seqnum & 0x0f0) >> 4);
	setnibble(payload, 3, (common.seqnum & 0x00f) >> 0);

	payload[2] = (common.devid & 0x000000ff) >> 0;
	payload[3] = (common.devid & 0x0000ff00) >> 8;
	payload[4] = (common.devid & 0x00ff0000) >> 16;
	payload[5] = (common.devid & 0xff000000) >> 24;

	// Add message content
	if (!uplink.singlebit)
		for (i = 0; i < uplink.msglen; ++i)
			payload[6 + i] = uplink.msg[i];

	// Generate HMAC for payload (actually using a CBC-MAC algorithm)
	// Input for CBC-MAC algorithm is a repetition of the payload over the whole length of
	// all input blocks. If payload is longer than 16 byte, it two blocks are used; otherwise one.
	uint8_t payloadlen = 6 + (uplink.singlebit ? 0 : uplink.msglen);

	// Fill two 128bit-AES blocks with data to encrypt, even if maybe just one of them is used
	uint8_t data_to_encrypt[32];
	uint8_t j = 0;

	for (i = 0; i < 32; ++i) {
		data_to_encrypt[i] = payload[j];
		j = (j + 1) % payloadlen;
	}

	uint8_t blocknum = (payloadlen > 16 ? 2 : 1);

	uint8_t encrypted_data[32];
	aes_128_cbc_encrypt(encrypted_data, data_to_encrypt, blocknum * 16, common.key);

	// The length of the HMAC included in the frame depends on the length of the 
	// message. It is at least 2 bytes, but if the message has to be padded, the
	// first bytes of the HMAC are used as padding.
	uint8_t hmaclen = 2 + paddinglen;
	uint8_t payload_with_hmac[SFX_UL_MAX_PAYLOADLEN_WITH_HMAC];

	for (i = 0; i < payloadlen; ++i)
		payload_with_hmac[i] = payload[i];

	for (i = 0; i < hmaclen; ++i)
		payload_with_hmac[payloadlen + i] = encrypted_data[(blocknum - 1) * 16 + i];

	// Add CRC to message (CRC is inverted)
	uint8_t payload_with_hmac_length = payloadlen + hmaclen;
	uint16_t crc16 = ~SIGFOX_CRC_crc16(payload_with_hmac, payload_with_hmac_length);

	// Copy whole message to frame buffer including HMAC and CRC, for first transmission only
	for (i = 0; i < payload_with_hmac_length; ++i)
		encoded->payload[0][4 + i] = payload_with_hmac[i];

	encoded->payload[0][SFX_UL_HEADERLEN + payload_with_hmac_length + 0] = (crc16 & 0xff00) >> 8;
	encoded->payload[0][SFX_UL_HEADERLEN + payload_with_hmac_length + 1] = crc16 & 0xff;

	uint8_t totallen_bytes = SFX_UL_HEADERLEN + payload_with_hmac_length + SFX_UL_CRCLEN;
	encoded->framelen_nibbles = totallen_bytes * 2 - SFX_UL_PREAMBLELEN_NIBBLES;

	// Encode replica transmissions using (7, 5) convolutional code
	convcode(encoded->payload[0], encoded->payload[1], totallen_bytes, SFX_UL_HEADERLEN, 7);
	convcode(encoded->payload[0], encoded->payload[2], totallen_bytes, SFX_UL_HEADERLEN, 5);
}

sfx_uld_err sfx_uplink_decode(sfx_ul_encoded to_decode, sfx_ul_plain *uplink_out, sfx_commoninfo *common_out)
{
	uint8_t *frame = to_decode.payload[0];

	// only odd nibble numbers can naturally occur - discard all frames with even nibble numbers
	if (to_decode.framelen_nibbles % 2 == 0)
		return SFX_ULD_ERR_MSGLEN_EVEN;

	uint16_t frametype = ((frame[0] & 0xf0) << 4) | ((frame[0] & 0x0f) << 4) | ((frame[1] & 0xf0) >> 4);

	// find replica / length that matches given frame type best (lowest hamming distance)
	uint8_t replica;
	uint8_t msglen_type;

	uint8_t best_replica = 4;
	uint8_t best_msglen_type = 5;
	uint8_t lowest_hammingdistance = 13;
	for (replica = 0; replica < 3; ++replica) {
		for (msglen_type = 0; msglen_type < 5; ++msglen_type) {
			uint8_t hammingdistance = __builtin_popcount(frametypes[replica][msglen_type] ^ frametype);

			if (hammingdistance < lowest_hammingdistance) {
				lowest_hammingdistance = hammingdistance;
				best_replica = replica;
				best_msglen_type = msglen_type;
			}
		}
	}

	// check if msglen_type matches given frame length
	if (best_msglen_type == 0) {
		if (to_decode.framelen_nibbles != SFX_UL_TOTALLEN_WITHOUT_PAYLOAD)
			return SFX_ULD_ERR_FTYPE_MISMATCH;
	}
	// TODO: check for other values of best_msglen_type

	uplink_out->singlebit = (best_msglen_type == 0);

	printf("best_replica: %d, best_msglen_type: %d\n", best_replica, best_msglen_type);

	return SFX_ULD_ERR_NONE;
}
