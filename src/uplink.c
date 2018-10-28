#include <string.h>
#include <stdio.h>

#include "sigfox_mac.h"
#include "sigfox_crc.h"
#include "uplink.h"
#include "common.h"

/**
 * @brief content of Sigfox's 5-nibble (::SFX_UL_PREAMBLELEN_NIBBLES) uplink preamble, only use first 5 nibbles
 */
uint8_t SFX_UL_PREAMBLE[] = {
	0xaa, 0xaa, 0xa0
};

/**
 * @brief set nibble (4 bits) in buffer to value
 * @param buffer buffer to modify
 * @param nibble index of nibble in buffer, 0-255
 * @param value value to set the nibble to, only the 4 lower bits are used
 */
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

/**
 * @brief get nibble (4 bits) from buffer
 * @param buffer buffer to read from
 * @param nibble index of nibble in buffer, 0-255
 * @return value of nibble, only the 4 lower bits are used
 */
uint8_t getnibble(uint8_t *buffer, uint8_t nibble)
{
	uint8_t byte = nibble / 2;
	bool highnibble = (nibble % 2) == 0;

	return highnibble ? (buffer[byte] & 0xf0) >> 4 : buffer[byte] & 0x0f;
}

/**
 * @brief read unsigned integer value from arbitrary nibble offset in buffer
 * @param buffer buffer to read from
 * @offset_nibbles offset at which the first (highest) nibble of the integer value is located
 * @length_nibbles length of unsigned integer value, in nibbles (up to 8)
 * @return 32-bit unsigned integer value that was read
 */
uint32_t getvalue_nibbles(uint8_t *buffer, uint8_t offset_nibbles, uint8_t length_nibbles)
{
	uint32_t retval = 0;
	for (uint8_t i = 0; i < length_nibbles; ++i)
		retval |= getnibble(buffer, offset_nibbles + i) << (4 * (length_nibbles - i - 1));

	return retval;
}

void setvalue_nibbles(uint8_t *buffer, uint8_t offset_nibbles, uint8_t length_nibbles, uint32_t value) {
	for (uint8_t i = 0; i < length_nibbles; ++i)
		setnibble(buffer, offset_nibbles + i, (value >> (4 * (length_nibbles - i - 1))) & 0x0f);
}

/**
 * @brief copy data from input buffer to output buffer at arbitrary nibble offsets
 * @param outbuffer pointer to output buffer
 * @param inbuffer pointer to input buffer
 * @param inoffset_nibbles offset at which to start reading from inbuffer, in nibbles
 * @param outoffset_nibbles offset at which to start writing to outbuffer, in nibbles
 * @param length_nibbles length of data to copy, in nibbles
 */
void memcpy_nibbles(uint8_t *outbuffer, uint8_t *inbuffer, uint8_t inoffset_nibbles, uint8_t outoffset_nibbles, uint8_t length_nibbles) {
	for (uint8_t i = 0; i < length_nibbles; ++i)
		setnibble(outbuffer, outoffset_nibbles + i, getnibble(inbuffer, inoffset_nibbles + i));
}

/**
 * @brief convolutional coder, multiplies input binary string U(X) with generator polynomial G(X) to produce output: V(X) = U(X) * G(X) under GF(2)-arithmetic
 * @param inbuffer input binary string, interpreted as polynomial U(X)
 * @param outbuffer output binary string, V(X)
 * @param length length of inbuffer in bits
 * @param offset_bits number of bits to skip in input, this many bits will just be ignored and not encoded
 * @param polynomial generator polynomial G(X) with maximum order 7
 */
void convcode(uint8_t *inbuffer, uint8_t *outbuffer, uint8_t length_bits, uint16_t offset_bits, uint8_t polynomial)
{
	uint8_t i;
	int8_t bit;
	uint8_t shiftregister = 0x00;

	uint8_t bitcount_in_last_byte = length_bits % 8;
	bool skip_last_byte = bitcount_in_last_byte == 0;

	for (i = offset_bits / 8; i < length_bits / 8 + 1; ++i) {
		bool is_first_byte = (i == offset_bits / 8);
		bool is_last_byte = (i == length_bits / 8);
		for (bit = is_first_byte ? 7 - offset_bits % 8 : 7; (bit >= is_last_byte ? 8 - bitcount_in_last_byte : 0) && !(is_last_byte && skip_last_byte); --bit) {
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

/**
 * @brief convolutional "decoder", does not take care of error correction, but simply reverses the convolutional coding applied by ::convcode. Realizes the polynomial division U(X) = V(X) / G(X) under GF(2)-arithmetic
 * @param inbuffer input binary string, interpreted as polynomial V(X)
 * @param outbuffer output binary string, U(X)
 * @param length_bits length of inbuffer in bits
 * @param offset_bits number of bits to skip in input, this many bits will just be ignored and not decoded
 * @param polynomial Generator polynomial G(X) with maximum order 7. Only polynomials with the LSB set (corresponds to "1") are supported.
 */
void unconvcode(uint8_t *inbuffer, uint8_t *outbuffer, uint8_t length_bits, uint16_t offset_bits, uint8_t polynomial) {
	uint8_t i;
	int8_t bit;
	uint8_t shiftregister = 0x00;

	uint8_t bitcount_in_last_byte = length_bits % 8;
	bool skip_last_byte = bitcount_in_last_byte == 0;

	for (i = offset_bits / 8; i < length_bits / 8 + 1; ++i) {
		bool is_first_byte = (i == offset_bits / 8);
		bool is_last_byte = (i == length_bits / 8);
		for (bit = is_first_byte ? 7 - offset_bits % 8 : 7; (bit >= is_last_byte ? 8 - bitcount_in_last_byte : 0) && !(is_last_byte && skip_last_byte); --bit) {
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
 * Column in 'frametypes' to packet (Flags + SN + Device ID + Payload + MAC) length
 */
uint8_t frametype_to_packetlen[] = {
	8, 9, 12, 16, 20
};

/**
 * @brief calculate MAC for given frame and given private key
 * @param packetcontent buffer containing all bytes in uplink packet except for the MAC tag itself (flags, SN, device ID, payload)
 * @param payloadlen length of payload inside packet in bytes (0 to 12, where 0 is for single-bit messages), length of `packetcontent` is thus 6 + payloadlen
 * @param key buffer containing the NAK (secret key)
 * @param mac output, message authentication code (MAC)
 * @return length of MAC in bytes
 */
uint8_t sfx_uplink_get_mac(uint8_t *packetcontent, uint8_t payloadlen, uint8_t *key, uint8_t *mac) {
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
	uint8_t maclen = SFX_UL_MIN_MACLEN + (payloadlen == 1 ? 0 : ((SFX_UL_MAX_PAYLOADLEN - payloadlen) % 4));
	memcpy(mac, &encrypted_data[(blocknum - 1) * 16], maclen);

	return maclen;
}

/**
 * @brief generate raw Sigfox uplink frame for the given frame contents
 * @param uplink the content of the payload to encode
 * @param common general information about the Sigfox object and its state
 * @param encoded output, raw encoded Sigfox uplink frame(s), including preamble
 * @return ::SFX_ULE_ERR_NONE if decoding was successful, otherwise some error defined in ::sfx_ule_err
 */
sfx_ule_err sfx_uplink_encode(sfx_ul_plain uplink, sfx_commoninfo common, sfx_ul_encoded *encoded)
{
	if (uplink.payloadlen > SFX_UL_MAX_PAYLOADLEN)
		return SFX_ULE_ERR_PAYLOAD_TOO_LONG;
	if (uplink.singlebit && uplink.payloadlen != 0)
		return SFX_ULE_SINGLEBIT_MISMATCH;

	uint8_t i;
	uint8_t replica;

	/*
	 * All replicas: Set frame type, indicates transmission count (initial / replica) and frame class
	 * Three general types of frame classes:
	 * Single bit (class A), 1 byte (class B), 4 / 8 / 12 bytes (classes C / D / E)
	 */
	for (replica = 0; replica < 3; ++replica) {
		uint16_t ftype;
		if (uplink.singlebit)
			ftype = frametypes[replica][0];
		else if (uplink.payloadlen == 1)
			ftype = frametypes[replica][1];
		else
			ftype = frametypes[replica][(uplink.payloadlen - 1) / 4 + 2];

		setnibble(encoded->frame[replica], 0, (ftype & 0xf00) >> 8);
		setnibble(encoded->frame[replica], 1, (ftype & 0x0f0) >> 4);
		setnibble(encoded->frame[replica], 2, (ftype & 0x00f) >> 0);
	}

	/*
	 * Construct packet consisting of flags, sequence number, device ID, message and MAC
	 * Length of MAC is at least 2, but may be extended
	 */
	uint8_t packet[SFX_UL_MAX_PACKETLEN];
	uint8_t flags = 0x0;

	/*
	 * Flags: Three special cases:
	 * - class A (single bit) messages: MSB of flag nibble is always 1, second bit is the message content (true / false)
	 * - class B: Length of MAC is always 2, thus flags are zero
	 * - class C / D / E: Length of MAC = 2 + <integer representation of upper two bits of flags>
	 */
	uint8_t maclen;
	if (uplink.singlebit) {
		maclen = SFX_UL_MIN_MACLEN;
		flags |= 0b1000 | ((uplink.payload[0] == 0) ? 0b0000 : 0b0100);
	} else if (uplink.payloadlen == 1) {
		maclen = SFX_UL_MIN_MACLEN;
	} else {
		maclen = (SFX_UL_MAX_PAYLOADLEN - uplink.payloadlen) % 4 + SFX_UL_MIN_MACLEN;
		flags |= (maclen - 2) << 2;
	}

	// Set downlink bit in flags if requested
	if (uplink.request_downlink)
		flags |= 0b0010;

	setnibble(packet, 0, flags);

	/*
	 * Sequence Number (SN): 12 bits
	 */
	setnibble(packet, 1, (common.seqnum & 0xf00) >> 8);
	setnibble(packet, 2, (common.seqnum & 0x0f0) >> 4);
	setnibble(packet, 3, (common.seqnum & 0x00f) >> 0);

	/*
	 * Device ID: Little Endian format
	 */
	packet[2] = (common.devid & 0x000000ff) >> 0;
	packet[3] = (common.devid & 0x0000ff00) >> 8;
	packet[4] = (common.devid & 0x00ff0000) >> 16;
	packet[5] = (common.devid & 0xff000000) >> 24;

	/*
	 * Payload
	 */
	if (!uplink.singlebit)
		for (i = 0; i < uplink.payloadlen; ++i)
			packet[6 + i] = uplink.payload[i];

	/*
	 * Message Authentication Code (MAC)
	 * The length of the MAC in the frame depends on the length of the payload.
	 * It is at least 2 bytes long, but can be extended to 3 / 4 / 5 bytes for frame classes C / D / E.
	 */
	uint8_t mac[SFX_UL_MAX_MACLEN];
	sfx_uplink_get_mac(packet, uplink.payloadlen, common.key, mac);
	uint8_t mac_offset = (SFX_UL_FLAGLEN_NIBBLES + SFX_UL_SNLEN_NIBBLES + SFX_UL_DEVIDLEN_NIBBLES) / 2 + (uplink.singlebit ? 0 : uplink.payloadlen);

	for (i = 0; i < maclen; ++i)
		packet[mac_offset + i] = mac[i];

	/*
	 * Copy whole packet to frame buffer, including MAC and CRC, for first transmission only
	 */
	uint8_t packetlen = mac_offset + maclen;
	memcpy_nibbles(encoded->frame[0], packet, 0, SFX_UL_FTYPELEN_NIBBLES, packetlen * 2);

	/*
	 * Add CRC to frame, takes care of bitwise inversion of CRC value
	 */
	uint16_t crc16 = ~SIGFOX_CRC_crc16(packet, packetlen);
	setvalue_nibbles(encoded->frame[0], SFX_UL_FTYPELEN_NIBBLES + packetlen * 2, 4, crc16);
	encoded->framelen_nibbles = SFX_UL_FTYPELEN_NIBBLES + packetlen * 2 + SFX_UL_CRCLEN_NIBBLES;

	/*
	 * Encode replica transmissions using (7, 5) convolutional code
	 */
	convcode(encoded->frame[0], encoded->frame[1], encoded->framelen_nibbles * 4, SFX_UL_FTYPELEN_NIBBLES * 4, 07);
	convcode(encoded->frame[0], encoded->frame[2], encoded->framelen_nibbles * 4, SFX_UL_FTYPELEN_NIBBLES * 4, 05);

	return SFX_ULE_ERR_NONE;
}

/**
 * @brief retrieve contents of Sigfox uplink from given raw frame
 * @param to_decode the raw contents of the Sigfox uplink frame to decode, only first frame is processed (can be initial transmission or any replica frame)
 * @param uplink_out output, decoded plain contents of uplink frame
 * @param common general information about the Sigfox object and its state: NAK is an optional input and only required, if MAC tag checking is enabled. Sequence number and and device ID fileds are used as outputs
 * @param check_mac: If true, check MAC tag of uplink frame. In this case, a valid NAK has to be provided.
 * @return ::SFX_ULD_ERR_NONE if decoding was successful, otherwise some error defined in ::sfx_uld_err
 */
sfx_uld_err sfx_uplink_decode(sfx_ul_encoded to_decode, sfx_ul_plain *uplink_out, sfx_commoninfo *common, bool check_mac)
{
	uint8_t *frame = to_decode.frame[0];

	// only odd nibble numbers can naturally occur - discard all frames with even nibble numbers
	if (to_decode.framelen_nibbles % 2 == 0)
		return SFX_ULD_ERR_FRAMELEN_EVEN;

	/*
	 * Find frame type value from table (indicates replica number / frame length) that matches contained
	 * frame type best (lowest hamming distance). This way, we can correct up to two erroneous bits
	 * inside the frame type field.
	*/
	uint16_t frametype = ((frame[0] & 0xf0) << 4) | ((frame[0] & 0x0f) << 4) | ((frame[1] & 0xf0) >> 4);
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

	// length of packet (Flags + SN + Device ID + Payload + MAC) in bytes
	uint8_t packetlen_bytes = frametype_to_packetlen[best_payloadlen_type];

	// check if frame length indicated by frame type matches actual length of frame
	if (to_decode.framelen_nibbles != SFX_UL_FTYPELEN_NIBBLES + packetlen_bytes * 2 + SFX_UL_CRCLEN_NIBBLES)
		return SFX_ULD_ERR_FTYPE_MISMATCH;

	uplink_out->singlebit = (best_payloadlen_type == 0);

	/*
	 * Just allocate the maximum possible frame length (even if it isn't necessary),
	 * so that we don't have to depend on stdlib.h for malloc. Allocates one more nibble than
	 * required because frames have an odd-nibble length, but we can only allocate bytes.
	 */
	uint8_t frame_plain[SFX_UL_MAX_FRAMELEN - SFX_UL_PREAMBLELEN_NIBBLES / 2];
	uint8_t ceil_framelen_bytes = (to_decode.framelen_nibbles + 1) / 2;
	if (best_replica == 0)
		memcpy(frame_plain, frame, ceil_framelen_bytes);
	else if (best_replica == 1)
		unconvcode(frame, frame_plain, ceil_framelen_bytes * 8, SFX_UL_FTYPELEN_NIBBLES * 4, 07);
	else if (best_replica == 2)
		unconvcode(frame, frame_plain, ceil_framelen_bytes * 8, SFX_UL_FTYPELEN_NIBBLES * 4, 05);

	/*
	 * Extract basic metadata from uplink frame
	 */
	#define FLAGS_OFFSET_NIBBLES SFX_UL_FTYPELEN_NIBBLES
	#define SN_OFFSET_NIBBLES FLAGS_OFFSET_NIBBLES + SFX_UL_FLAGLEN_NIBBLES
	#define DEVID_OFFSET_NIBBLES SN_OFFSET_NIBBLES + SFX_UL_SNLEN_NIBBLES
	#define PAYLOAD_OFFSET_NIBBLES DEVID_OFFSET_NIBBLES + SFX_UL_DEVIDLEN_NIBBLES

	// Device ID is encoded in little endian format - reverse byte order
	uint32_t devid_le = getvalue_nibbles(frame_plain, DEVID_OFFSET_NIBBLES, SFX_UL_DEVIDLEN_NIBBLES);
	common->devid = (devid_le & 0x000000ff) << 24;
	common->devid |= (devid_le & 0x0000ff00) << 8;
	common->devid |= (devid_le & 0x00ff0000) >> 8;
	common->devid |= (devid_le & 0xff000000) >> 24;
	common->seqnum = getvalue_nibbles(frame_plain, SN_OFFSET_NIBBLES, SFX_UL_SNLEN_NIBBLES);

	// Read and interpret flags
	uint8_t flags = getvalue_nibbles(frame_plain, 3, 1);
	uint8_t maclen = SFX_UL_MIN_MACLEN + (uplink_out->singlebit ? 0 : flags >> 2);
	uplink_out->request_downlink = flags & 0b0010 ? true : false;
	uplink_out->payloadlen = packetlen_bytes - (SFX_UL_FLAGLEN_NIBBLES + SFX_UL_SNLEN_NIBBLES + SFX_UL_DEVIDLEN_NIBBLES) / 2 - maclen;

	// Copy frame's payload to uplink_out (decoded properties)
	if (!uplink_out->singlebit)
		memcpy_nibbles(uplink_out->payload, frame_plain, PAYLOAD_OFFSET_NIBBLES, 0, uplink_out->payloadlen * 2);
	else
		uplink_out->payload[0] = flags & 0b0100 ? 0x01 : 0x00;

	/*
	 * Check CRC
	 * CRC is calculated from the frame contents starting at the flags
	 */
	uint8_t packet[SFX_UL_MAX_PACKETLEN];
	uint8_t crc16_offset_nibbles = SFX_UL_FTYPELEN_NIBBLES + packetlen_bytes * 2;

	memcpy_nibbles(packet, frame_plain, FLAGS_OFFSET_NIBBLES, 0, packetlen_bytes * 2);

	uint16_t crc16 = ~SIGFOX_CRC_crc16(packet, packetlen_bytes);
	uint16_t crc16_frame = getvalue_nibbles(frame_plain, crc16_offset_nibbles, SFX_UL_CRCLEN_NIBBLES);

	if (crc16 != crc16_frame)
		return SFX_ULD_ERR_CRC_INVALID;

	/*
	 * Check MAC (optional)
	 */
	if (check_mac) {
		uint8_t mac[SFX_UL_MAX_MACLEN];
		uint8_t maclen = sfx_uplink_get_mac(packet, uplink_out->payloadlen, common->key, mac);

		for (uint8_t i = 0; i < maclen; ++i)
			if (packet[packetlen_bytes - maclen + i] != mac[i])
				return SFX_ULD_ERR_MAC_INVALID;
	}

	return SFX_ULD_ERR_NONE;
}
