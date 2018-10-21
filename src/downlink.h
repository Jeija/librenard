#include <inttypes.h>
#include <stdbool.h>

#include "common.h"

#ifndef _DOWNLINK_H
#define _DOWNLINK_H

/*
 * Internal definitions, lengths in bytes
 * Frame field length definitions, see section 3.2 of Bachelor's Thesis
 * "Reverse Engineering of the Sigfox Radio Protocol and Implementation of an Alternative Sigfox Network Stack"
 */
#define SFX_DL_FRAMELEN 15

#define SFX_DL_PAYLOADOFFSET 4
#define SFX_DL_MACOFFSET 12
#define SFX_DL_CRCOFFSET 14

#define SFX_DL_PAYLOADLEN 8
#define SFX_DL_MACLEN 2
#define SFX_DL_CRCLEN 1

/*
 * Public interface:
 */
extern uint8_t SFX_DL_PREAMBLE[];

/// length of Sigfox's downlink preamble, in bytes
#define SFX_DL_PREAMBLELEN 13

/**
 * @brief properties that describe the encoded contents of a raw downlink frame after reception / before transmission
 */
typedef struct _s_sfx_dl_encoded {
	/// raw, scrambled contents of downlink frame *without* preamble, 15 bytes long
	uint8_t frame[SFX_DL_FRAMELEN];
} sfx_dl_encoded;

/**
 * @brief properties that describe the plain contents of a downlink frame after decoding or before encoding
 */
typedef struct _s_sfx_dl_plain {
	/// plaintext payload of downlink frame, always 8 bytes long
	uint8_t payload[SFX_DL_PAYLOADLEN];

	/// indicates whether CRC of downlink frame is valid, set by ::sfx_downlink_decode
	bool crc_ok;

	/// indicates whether MAC of downlink frame is valid, set by ::sfx_downlink_decode
	bool mac_ok;

	/// indicates whether FEC was applied during decoding, set by ::sfx_downlink_decode
	bool fec_corrected;
} sfx_dl_plain;

void sfx_downlink_decode(sfx_dl_encoded encoded, sfx_commoninfo common, sfx_dl_plain *decoded);
void sfx_downlink_encode(sfx_dl_plain to_encode, sfx_commoninfo common, sfx_dl_encoded *encoded);

#endif
