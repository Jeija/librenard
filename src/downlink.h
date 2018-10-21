#include <inttypes.h>
#include <stdbool.h>

#include "common.h"

#ifndef _DOWNLINK_H
#define _DOWNLINK_H

/*
 * Lengths in bytes
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

#define SFX_DL_PREAMBLELEN 13
extern uint8_t SFX_DL_PREAMBLE[];

typedef struct _s_sfx_dl_encoded {
	uint8_t frame[SFX_DL_FRAMELEN];
} sfx_dl_encoded;

typedef struct _s_sfx_dl_plain {
	uint8_t payload[SFX_DL_PAYLOADLEN];
	bool crc_ok;
	bool mac_ok;
	bool fec_corrected;
} sfx_dl_plain;

void sfx_downlink_decode(sfx_dl_encoded encoded, sfx_commoninfo common, sfx_dl_plain *decoded);
void sfx_downlink_encode(sfx_dl_plain to_encode, sfx_commoninfo common, sfx_dl_encoded *encoded);

#endif
