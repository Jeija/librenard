#include <inttypes.h>
#include <stdbool.h>

#include "common.h"

#ifndef _UPLINK_H
#define _UPLINK_H

extern uint8_t SFX_UL_PREAMBLE[];

/*
 * Lengths in bytes
 * Frame field length definitions, see section 2.2 of Bachelor's Thesis
 * "Reverse Engineering of the Sigfox Radio Protocol and Implementation of an Alternative Sigfox Network Stack"
 */
#define SFX_UL_MAX_FRAMELEN 26
#define SFX_UL_MAX_PACKETLEN 20
#define SFX_UL_MAX_MACLEN 5
#define SFX_UL_MIN_MACLEN 2
#define SFX_UL_MAX_PAYLOADLEN 12

/*
 * Lengths in nibbles
 */
#define SFX_UL_PREAMBLELEN_NIBBLES 5
#define SFX_UL_FTYPELEN_NIBBLES 3
#define SFX_UL_FLAGLEN_NIBBLES 1
#define SFX_UL_SNLEN_NIBBLES 3
#define SFX_UL_DEVIDLEN_NIBBLES 8
#define SFX_UL_MIN_MACLEN_NIBBLES (SFX_UL_MIN_MACLEN * 2)
#define SFX_UL_CRCLEN_NIBBLES 4

typedef struct _s_sfx_ul_plain {
	uint8_t payload[SFX_UL_MAX_PAYLOADLEN];
	uint8_t payloadlen;
	bool request_downlink;
	bool singlebit;
	bool replicas;
} sfx_ul_plain;

/*
 * framelen_nibbles is length of payload content (*without* preamble)
 * in nibbles
 */
typedef struct _s_sfx_ul_encoded {
	uint8_t frame[3][SFX_UL_MAX_FRAMELEN];
	uint8_t framelen_nibbles;
} sfx_ul_encoded;

/**
 * @typedef sfx_ule_err
 * @brief Set of errors that can occur during uplink frame encoding, returned by ::sfx_uplink_encode.
 */
typedef enum _s_sfx_ule_err {
	// length of payload is too high, does not fit in Sigfox uplink frame
	SFX_ULE_ERR_PAYLOAD_TOO_LONG,

	// single-bit uplink was transmitted, but payload length was not defined to be 0
	SFX_ULE_SINGLEBIT_MISMATCH,

	SFX_ULE_ERR_NONE
} sfx_ule_err;

/**
 * @typedef sfx_uld_err
 * @brief Set of errors that can occur during uplink frame decoding, returned by ::sfx_uplink_decode.
 */
typedef enum _s_sfx_uld_err {
	// number of nibbles in message frame is even; only odd lengths can naturally occur
	SFX_ULD_ERR_FRAMELEN_EVEN,

	// frame type doesn't match given messsage length
	SFX_ULD_ERR_FTYPE_MISMATCH,

	// frame's CRC16 doesn't match CRC16 computed from frame contents
	SFX_ULD_ERR_CRC_INVALID,

	// frame's MAC doesn't match MAC computed from frame contents (and private key)
	// can only occur if `check_mac` parameter to sfx_uplink_decode is set
	SFX_ULD_ERR_MAC_INVALID,

	SFX_ULD_ERR_NONE
} sfx_uld_err;

sfx_ule_err sfx_uplink_encode(sfx_ul_plain uplink, sfx_commoninfo common, sfx_ul_encoded *encoded);

/*
 * TODO: document
 * 'to_decode.payload' shall only contain one frame in this case,
 * sfx_uplink_decode can handle either first, second or third transmission
 * 'common' parameter is both used as input (common.key, optional if check_mac is set)
 * and as output (common.devid, common.seqnum)
 */
sfx_uld_err sfx_uplink_decode(sfx_ul_encoded to_decode, sfx_ul_plain *uplink_out, sfx_commoninfo *common, bool check_mac);

#endif
