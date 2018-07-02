#include <inttypes.h>
#include <stdbool.h>

#include "common.h"

#ifndef _UPLINK_H
#define _UPLINK_H

#define SFX_UL_MAX_FRAMELEN 26
#define SFX_UL_HEADERLEN 4
#define SFX_UL_MAX_PAYLOADLEN 18
#define SFX_UL_MAX_PAYLOADLEN_WITH_HMAC SFX_UL_MAX_PAYLOADLEN + 5
#define SFX_UL_CRCLEN 2

typedef struct _s_sfx_ul_plain {
	uint16_t seqnum;
	uint32_t devid;
	uint8_t msg[12];
	uint8_t msglen;
	uint8_t key[16];
	bool request_downlink;
	bool singlebit;
	bool replicas;
} sfx_ul_plain;

// Return value: Length of sigfox frame
uint8_t sfx_uplink_encode(sfx_ul_plain uplink, sfx_commoninfo common, uint8_t frames[3][SFX_UL_MAX_FRAMELEN]);

#endif
