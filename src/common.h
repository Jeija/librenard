#ifndef _COMMON_H
#define _COMMON_H

/**
 * @brief data points that are common to both uplink encoding and downlink decoding, describe static properties (device ID, NAK) and state of a Sigfox object
 */
typedef struct _s_sfx_commoninfo {
	/// current uplink sequence number (for uplink) or sequence number of corresponding uplink (for downlink), 12 bits
	uint16_t seqnum;

	/// device ID of Sigfox object, 4 bytes represented as a 32-bit unsigned integer
	uint32_t devid;

	/// NAK (Network Authentication Key = secret key = private key) of Sigfox object, 128 bits / 16 bytes in total
	uint8_t key[16];
} sfx_commoninfo;

#endif
