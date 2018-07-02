#ifndef _COMMON_H
#define _COMMON_H

/*
 * Data points that are common to both uplink encoding
 * and downlink decoding.
 */

typedef struct _s_sfx_commoninfo {
	uint16_t seqnum;
	uint32_t devid;
	uint8_t key[16];
} sfx_commoninfo;

#endif
