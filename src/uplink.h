#include <inttypes.h>
#include <stdbool.h>

#include "common.h"

#ifndef _UPLINK_H
#define _UPLINK_H

/*
 * SFX_UL_HEADERLEN: length of preamble (5 nibbles) and frame type (3 nibbles)
 * combined, in bytes; everything after SFX_UL_HEADERLEN is encoded using
 * the (7, 5) convolutional code in the second and third transmission.
 * SFX_UL_PAYLOADOFFSET: offset in bytes at which payload (message) starts,
 * after preamble (5 nibbles), frame type (3 nibbles), flags (1 nibble), SN (3 nibbles),
 * device ID (8 nibbles)
 */
#define SFX_UL_HEADERLEN 4
#define SFX_UL_PAYLOADOFFSET 10 /* TODO: Unused */
#define SFX_UL_MAX_FRAMELEN 26
#define SFX_UL_MAX_PAYLOADLEN 18
#define SFX_UL_MAX_PAYLOADLEN_WITH_HMAC SFX_UL_MAX_PAYLOADLEN + 5
#define SFX_UL_MAX_HMACLEN 5
#define SFX_UL_CRCLEN 2
#define SFX_UL_HMACRESERVELEN 2

/*
 * All relevant lengths converted to nibbles
 * 'HMACRESERVED' is the 2 bytes that are reserved for the HMAC
 */
#define SFX_UL_PREAMBLELEN_NIBBLES 5
#define SFX_UL_FTYPELEN_NIBBLES 3
#define SFX_UL_FLAGLEN_NIBBLES 1
#define SFX_UL_SNLEN_NIBBLES 3
#define SFX_UL_DEVIDLEN_NIBBLES 8
#define SFX_UL_HMACRESERVERLEN_NIBBLES (SFX_UL_HMACRESERVELEN * 2)
#define SFX_UL_CRCLEN_NIBBLES (SFX_UL_CRCLEN * 2)
#define SFX_UL_TOTALLEN_WITHOUT_PAYLOAD_NIBBLES (SFX_UL_FTYPELEN_NIBBLES + SFX_UL_FLAGLEN_NIBBLES + SFX_UL_SNLEN_NIBBLES + SFX_UL_DEVIDLEN_NIBBLES + SFX_UL_HMACRESERVERLEN_NIBBLES + SFX_UL_CRCLEN_NIBBLES)

typedef struct _s_sfx_ul_plain {
	uint8_t msg[12];
	uint8_t msglen;
	bool request_downlink;
	bool singlebit;
	bool replicas;
} sfx_ul_plain;

/*
 * framelen_nibbles is length of payload content (*without* preamble)
 * in nibbles
 */
typedef struct _s_sfx_ul_encoded {
	uint8_t payload[3][SFX_UL_MAX_FRAMELEN];
	uint8_t framelen_nibbles;
} sfx_ul_encoded;

typedef enum _s_sfx_uld_err {
	// number of nibbles in message frame is even; only odd lengths can naturally occur
	SFX_ULD_ERR_MSGLEN_EVEN,

	// frame type doesn't match given messsage length
	SFX_ULD_ERR_FTYPE_MISMATCH,

	// frame's CRC16 doesn't match CRC16 computed from frame contents
	SFX_ULD_ERR_CRC_INVALID,

	// frame's HMAC doesn't match HMAC computed from frame contents (and private key)
	// can only occur if `check_hmac` parameter to sfx_uplink_decode is set
	SFX_ULD_ERR_HMAC_INVALID,

	SFX_ULD_ERR_NONE
} sfx_uld_err;

/*
 * TODO: document
 */
void sfx_uplink_encode(sfx_ul_plain uplink, sfx_commoninfo common, sfx_ul_encoded *encoded);

/*
 * TODO: document
 * 'to_decode.payload' shall only contain one frame in this case,
 * sfx_uplink_decode can handle either first, second or third transmission
 * 'common' parameter is both used as input (common.key, optional if check_hmac is set)
 * and as output (common.devid, common.seqnum)
 */
sfx_uld_err sfx_uplink_decode(sfx_ul_encoded to_decode, sfx_ul_plain *uplink_out, sfx_commoninfo *common, bool check_hmac);

#endif
