#include <byteswap.h>
#include <string.h>
#include <stdio.h>

#include "sigfox_hmac.h"
#include "sigfox_crc.h"
#include "uplink.h"
#include "common.h"

void setnibble(uint8_t *buffer, uint8_t nibble, uint8_t value)
{
	value &= 0x0f;
	uint8_t byte = nibble / 2;
	bool highnibble = (nibble % 2) == 0;

	if (highnibble)
		buffer[byte] = (buffer[byte] & 0x0f) | (value << 4);
	else
		buffer[byte] = (buffer[byte] & 0xf0) | value;
}

uint8_t getnibble(uint8_t *buffer, uint8_t nibble)
{
	uint8_t byte = nibble / 2;
	bool highnibble = (nibble % 2) == 0;

	return highnibble ? (buffer[byte] & 0xf0) >> 4 : buffer[byte] & 0x0f;
}

// read value from even / non-even nibble offset in buffer
uint32_t getvalue(uint8_t *buffer, uint8_t offset_nibbles, uint8_t length_nibbles)
{
	uint32_t retval = 0;
	for (uint8_t i = 0; i < length_nibbles; ++i)
		retval |= getnibble(buffer, offset_nibbles + i) << (4 * (length_nibbles - i - 1));

	return retval;
}

// read outbuffer from even / non-even nibble offset in inbuffer
void readbuffer(uint8_t *inbuffer, uint8_t *outbuffer, uint8_t offset_nibbles, uint8_t length_nibbles) {
	for (uint8_t i = 0; i < length_nibbles; ++i)
		setnibble(outbuffer, i, getnibble(inbuffer, offset_nibbles + i));
}

/*
 * Convolutional code encoder
 * The encoder looks at a maximum of 8 bits at a time, so the polynomial may not be of higher order
 */
void convcode(uint8_t *inbuffer, uint8_t *outbuffer, uint8_t length, uint16_t offset_bits, uint8_t polynomial)
{
	uint8_t i;
	int8_t bit;
	uint8_t shiftregister = 0x00;

	for (i = offset_bits / 8; i < length; ++i) {
		for (bit = i == offset_bits / 8 ? 7 - offset_bits % 8 : 7; bit >= 0; --bit) {
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
 * Convolutional code "decoder"
 * This decoder does not take care of any error correction, it simply reverses the convolutional coding
 * applied by 'convcode'. LSB of 'polynomial' must be set (number must therefore be odd)!
 * This is basically polynomial division under GF(2) arithmetic.
 */
void unconvcode(uint8_t *inbuffer, uint8_t *outbuffer, uint8_t length, uint16_t offset_bits, uint8_t polynomial) {
	uint8_t i;
	int8_t bit;
	uint8_t shiftregister = 0x00;

	for (i = offset_bits / 8; i < length; ++i) {
		for (bit = i == offset_bits / 8 ? 7 - offset_bits % 8 : 7; bit >= 0; --bit) {
			shiftregister = (shiftregister >> 1);
			bool in = (0x01 & (inbuffer[i] >> bit)) != 0;
			bool out = (shiftregister & 0x01) ^ in;

			if (out)
				shiftregister ^= polynomial;

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

/*
 * Translation table:
 * column in 'frametypes' to message payload length *including*
 * HMAC padded into payload field in bytes
 */
uint8_t payloadlen_type_to_addlen[] = {
	0, 1, 4, 8, 12
};

/**
 * @brief Calculate MAC for given frame and given private key
 * @param packetcontent Buffer containing all bytes in uplink packet except for the MAC tag itself (flags, SN, device ID, payload)
 * @param payloadlen Length of payload inside packet in bytes (0 to 12, where 0 is for single-bit messages), length of `packetcontent` is thus 6 + payloadlen
 * @param key Buffer containing the NAK (secret key)
 * @param mac Output, message authentication code (MAC)
 * @return Length of MAC in bytes
 */
uint8_t sfx_uplink_get_hmac(uint8_t *packetcontent, uint8_t payloadlen, uint8_t *key, uint8_t *mac) {
	// Fill two 128bit-AES blocks with data to encrypt, even if maybe just one of them is used
	// authentic_data_length: not only the payload, but also flags, SN and device id are begin protected
	// (authenticity checked) by MAC, therefore the length of data to be encrypted is greater than just
	// the message payload
	#define ADDITIONAL_LENGTH_BYTES ((SFX_UL_FLAGLEN_NIBBLES + SFX_UL_SNLEN_NIBBLES + SFX_UL_DEVIDLEN_NIBBLES) / 2)
	uint8_t authentic_data_length = ADDITIONAL_LENGTH_BYTES + payloadlen;
	uint8_t data_to_encrypt[32];
	uint8_t j = 0;
	for (uint8_t i = 0; i < 32; ++i) {
		data_to_encrypt[i] = packetcontent[j];
		j = (j + 1) % authentic_data_length;
	}

	// If authenticity-checked data is longer than one AES block (128 bits = 16 bytes),
	// use two blocks
	uint8_t blocknum = (authentic_data_length > 16 ? 2 : 1);

	// Encrypt authenticity-checked data with 'private' AES key,
	// beginning of encrypted_data is mac
	uint8_t encrypted_data[32];
	aes_128_cbc_encrypt(encrypted_data, data_to_encrypt, blocknum * 16, key);

	// The length of the MAC included in the frame depends on the length of the 
	// message. It is at least 2 bytes, but if the message has to be padded, the
	// first bytes of the MAC are used as padding.
	// Special case: Single-byte messages have a special frame type, don't have
	// to be padded.
	uint8_t maclen = SFX_UL_HMACRESERVELEN + (payloadlen == 1 ? 0 : ((12 - payloadlen) % 4));
	memcpy(mac, &encrypted_data[(blocknum - 1) * 16], maclen);

	return maclen;
}

// TODO: fix nomenclaature ("payload")
// TODO: #define offsets with constants in header
// TODO: output should not contain preamble, renard should take of that
/**
 * @brief: Generate raw Sigfox uplink frame for the given frame contents
 * @param uplink: The content of the payload to encode
 * @param common: General information about the Sigfox object and its state
 * @param encoded: Output, raw encoded Sigfox uplink frame(s), including preamble
 */
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
	// all input blocks. If payload is longer than 16 byte, if two blocks are used; otherwise one.
	uint8_t hmac[SFX_UL_MAX_HMACLEN];
	uint8_t hmaclen = sfx_uplink_get_hmac(payload, uplink.msglen, common.key, hmac);

	// The length of the HMAC included in the frame depends on the length of the 
	// message. It is at least 2 bytes, but if the message has to be padded, the
	// first bytes of the HMAC are used as padding.
	uint8_t payloadlen = 6 + (uplink.singlebit ? 0 : uplink.msglen);
	uint8_t payload_with_hmac[SFX_UL_MAX_PAYLOADLEN_WITH_HMAC];

	for (i = 0; i < payloadlen; ++i)
		payload_with_hmac[i] = payload[i];

	for (i = 0; i < hmaclen; ++i)
		payload_with_hmac[payloadlen + i] = hmac[i];

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
	convcode(encoded->payload[0], encoded->payload[1], totallen_bytes, SFX_UL_HEADERLEN * 8, 7);
	convcode(encoded->payload[0], encoded->payload[2], totallen_bytes, SFX_UL_HEADERLEN * 8, 5);
}

/**
 * @brief: Retrieve contents of Sigfox uplink from given raw frame
 * @param to_decode: The raw contents of the Sigfox uplink frame to decode, without preamble (any replica)
 * @param uplink_out: Output, decoded plain contents of uplink frame
 * @param common: General information about the Sigfox object and its state. NAK is optional and only required, if MAC tag checking is enabled.
 * @param check_mac: If true, check MAC tag of uplink frame. In this case, a valid NAK has to be provided.
 * @return ::SFX_ULD_ERR_NONE if decoding was successful, otherwise some error defined in ::sfx_uld_err
 */
sfx_uld_err sfx_uplink_decode(sfx_ul_encoded to_decode, sfx_ul_plain *uplink_out, sfx_commoninfo *common, bool check_mac)
{
	uint8_t *frame = to_decode.payload[0];

	// only odd nibble numbers can naturally occur - discard all frames with even nibble numbers
	if (to_decode.framelen_nibbles % 2 == 0)
		return SFX_ULD_ERR_MSGLEN_EVEN;

	uint16_t frametype = ((frame[0] & 0xf0) << 4) | ((frame[0] & 0x0f) << 4) | ((frame[1] & 0xf0) >> 4);

	// find replica / length that matches given frame type best (lowest hamming distance)
	// this way, we can correct single-bit transmission errors of the frame type
	uint8_t replica;
	uint8_t payloadlen_type;

	uint8_t best_replica = 4;
	uint8_t best_payloadlen_type = 5;
	uint8_t lowest_hammingdistance = 13;
	for (replica = 0; replica < 3; ++replica) {
		for (payloadlen_type = 0; payloadlen_type < 5; ++payloadlen_type) {
			uint8_t hammingdistance = __builtin_popcount(frametypes[replica][payloadlen_type] ^ frametype);

			if (hammingdistance < lowest_hammingdistance) {
				lowest_hammingdistance = hammingdistance;
				best_replica = replica;
				best_payloadlen_type = payloadlen_type;
			}
		}
	}

	// length of payload in bytes *including* part of HMAC that is padded to end of payload
	uint8_t payloadlen_bytes = payloadlen_type_to_addlen[best_payloadlen_type];

	// Check if provided payload length matches payload length in frame type
	if (to_decode.framelen_nibbles != SFX_UL_TOTALLEN_WITHOUT_PAYLOAD_NIBBLES + payloadlen_bytes * 2)
		return SFX_ULD_ERR_FTYPE_MISMATCH;

	uplink_out->singlebit = (best_payloadlen_type == 0);

	// just allocate the maximum possible frame length (even if it isn't necessary),
	// so that we don't have to depend on stdlib.h for malloc
	uint8_t frame_plain[SFX_UL_MAX_FRAMELEN - SFX_UL_PREAMBLELEN_NIBBLES / 2];

	// ceiled frame length in bytes
	uint8_t ceil_framelen_bytes = (to_decode.framelen_nibbles + 1) / 2;
	if (best_replica == 0)
		memcpy(frame_plain, frame, ceil_framelen_bytes);
	else if (best_replica == 1)
		unconvcode(frame, frame_plain, ceil_framelen_bytes, SFX_UL_FTYPELEN_NIBBLES * 4, 7);
	else if (best_replica == 2)
		unconvcode(frame, frame_plain, ceil_framelen_bytes, SFX_UL_FTYPELEN_NIBBLES * 4, 5);
	/*
	 * Extract basic metadata from uplink frame
	 */
	#define FLAGS_OFFSET_NIBBLES SFX_UL_FTYPELEN_NIBBLES
	#define SN_OFFSET_NIBBLES FLAGS_OFFSET_NIBBLES + SFX_UL_FLAGLEN_NIBBLES
	#define DEVID_OFFSET_NIBBLES SN_OFFSET_NIBBLES + SFX_UL_SNLEN_NIBBLES
	#define PAYLOAD_OFFSET_NIBBLES DEVID_OFFSET_NIBBLES + SFX_UL_DEVIDLEN_NIBBLES

	// Device ID is encoded in little endian format - reverse byte order
	uint32_t devid_le = getvalue(frame_plain, DEVID_OFFSET_NIBBLES, SFX_UL_DEVIDLEN_NIBBLES);
	common->devid = __bswap_32(devid_le);
	common->seqnum = getvalue(frame_plain, SN_OFFSET_NIBBLES, SFX_UL_SNLEN_NIBBLES);

	// Read and interpret flags
	uint8_t flags = getvalue(frame_plain, 3, 1);
	uplink_out->request_downlink = flags & 0b0010 ? true : false;
	uint8_t paddinglen = uplink_out->singlebit ? 0 : flags >> 2;
	uplink_out->msglen = payloadlen_bytes - paddinglen;

	// Copy payload / message to uplink_out
	if (!uplink_out->singlebit)
		readbuffer(frame_plain, uplink_out->msg, PAYLOAD_OFFSET_NIBBLES, uplink_out->msglen * 2);
	else
		uplink_out->msg[0] = flags & 0b0100 ? 0x01 : 0x00;

	/*
	 * Check CRC
	 * CRC is calculated from the frame contents starting at the flags
	 * 'framecontent' is the section of the frame from flags to HMAC
	 * 'framecontent_len_nibbles' is even (no half-bytes)
	 */
	#define FRAMECONTENT_NIBBLES_WITHOUT_PAYLOAD SFX_UL_FLAGLEN_NIBBLES + SFX_UL_SNLEN_NIBBLES + SFX_UL_DEVIDLEN_NIBBLES + SFX_UL_HMACRESERVERLEN_NIBBLES
	uint8_t framecontent[SFX_UL_MAX_PAYLOADLEN];
	uint8_t framecontent_len_nibbles = FRAMECONTENT_NIBBLES_WITHOUT_PAYLOAD + 2 * payloadlen_bytes;
	uint8_t framecontent_len = framecontent_len_nibbles / 2;

	readbuffer(frame_plain, framecontent, FLAGS_OFFSET_NIBBLES, framecontent_len_nibbles);

	uint8_t crc16_offset_nibbles = SFX_UL_FTYPELEN_NIBBLES + framecontent_len_nibbles;

	uint16_t crc16 = ~SIGFOX_CRC_crc16(framecontent, framecontent_len);
	uint16_t crc16_frame = getvalue(frame_plain, crc16_offset_nibbles, SFX_UL_CRCLEN_NIBBLES);

	if (crc16 != crc16_frame)
		return SFX_ULD_ERR_CRC_INVALID;

	/*
	 * Check HMAC (optional)
	 */
	if (check_mac) {
		uint8_t hmac[SFX_UL_MAX_HMACLEN];
		uint8_t hmaclen = sfx_uplink_get_hmac(framecontent, uplink_out->msglen, common->key, hmac);

		for (uint8_t i = 0; i < hmaclen; ++i)
			if (framecontent[framecontent_len - hmaclen + i] != hmac[i])
				return SFX_ULD_ERR_HMAC_INVALID;
	}

	return SFX_ULD_ERR_NONE;
}
