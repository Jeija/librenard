#include <inttypes.h>
#include <stdbool.h>

#include "common.h"

#ifndef _DOWNLINK_H
#define _DOWNLINK_H

#define SFX_DL_PAYLOADLEN 15
#define SFX_DL_MSGLEN 8
#define SFX_DL_MSGOFFSET 4
#define SFX_DL_HMACOFFSET 12
#define SFX_DL_HMACLEN 2
#define SFX_DL_CRCOFFSET 14
#define SFX_DL_CRCLEN 1

#define SFX_DL_PREAMBLELEN 13
extern uint8_t SFX_DL_PREAMBLE[];

typedef struct _s_sfx_dl_encoded {
	uint8_t payload[SFX_DL_PAYLOADLEN];
} sfx_dl_encoded;

typedef struct _s_sfx_dl_plain {
	uint8_t msg[SFX_DL_MSGLEN];
	bool crc_ok;
	bool hmac_ok;
	bool fec_corrected;
} sfx_dl_plain;

void sfx_downlink_decode(sfx_dl_encoded encoded, sfx_commoninfo common, sfx_dl_plain *decoded);
void sfx_downlink_encode(sfx_dl_plain to_encode, sfx_commoninfo common, sfx_dl_encoded *encoded);

#endif
