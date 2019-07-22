#include <inttypes.h>
#include <stdbool.h>

#include "common.h"

#ifndef _UPLINK_H
#define _UPLINK_H

/*
 * Internal definitions, lengths in bytes
 * Frame field length definitions, see section 2.2 of Bachelor's Thesis
 * "Reverse Engineering of the Sigfox Radio Protocol and Implementation of an Alternative Sigfox Network Stack"
 */
#define SFX_UL_MAX_FRAMELEN 24
#define SFX_UL_MAX_PACKETLEN 20
#define SFX_UL_MAX_MACLEN 5
#define SFX_UL_MIN_MACLEN 2
#define SFX_UL_MAX_PAYLOADLEN 12

/*
 * Lengths in nibbles
 */
#define SFX_UL_FTYPELEN_NIBBLES 3
#define SFX_UL_FLAGLEN_NIBBLES 1
#define SFX_UL_SNLEN_NIBBLES 3
#define SFX_UL_DEVIDLEN_NIBBLES 8
#define SFX_UL_MIN_MACLEN_NIBBLES (SFX_UL_MIN_MACLEN * 2)
#define SFX_UL_CRCLEN_NIBBLES 4

/*
 * Public Interface:
 */
extern uint8_t SFX_UL_PREAMBLE[];

/// length of Sigfox's uplink preamble, in nibbles
#define SFX_UL_PREAMBLELEN_NIBBLES 5

/**
 * @brief properties that describe the plain contents of an uplink frame, that is the frame contents before encoding or after decoding
 */
typedef struct _s_sfx_ul_plain {
	/// payload of uplink frame with length between 0 and 12 bytes
	uint8_t payload[SFX_UL_MAX_PAYLOADLEN];

	/// length of payload
	uint8_t payloadlen;

	/// indicates whether downlink request flag should be / is set
	bool request_downlink;

	/// indicates whether uplink frame is a single-bit (class A) frame
	bool singlebit;

	/// indicates whether replica frames (true) or only initial transmission (false) should be generated, only used for encoding (::sfx_uplink_encode)
	bool replicas;
} sfx_ul_plain;

/**
 * @brief properties that describe the encoded contents of a raw uplink frame after reception / before transmission
 */
typedef struct _s_sfx_ul_encoded {
	/// frame content of initial transmission and up to two replicas; ::sfx_uplink_decode only uses first frame, *without* preamble, up to 47 nibbles length
	uint8_t frame[3][SFX_UL_MAX_FRAMELEN];

	/// length of frame (length of initial transmission and replicas is identical) in nibbles (4 bits), *excluding* preamble, must be an odd number
	uint8_t framelen_nibbles;
} sfx_ul_encoded;

/**
 * @brief set of errors that can occur during uplink frame encoding, returned by ::sfx_uplink_encode
 */
typedef enum _s_sfx_ule_err {
	/// no error occured, success
	SFX_ULE_ERR_NONE = 0,

	/// length of payload is too high, does not fit in Sigfox uplink frame
	SFX_ULE_ERR_PAYLOAD_TOO_LONG,

	/// single-bit uplink was transmitted, but payload length was not defined to be 0
	SFX_ULE_SINGLEBIT_MISMATCH
} sfx_ule_err;

/**
 * @brief set of errors that can occur during uplink frame decoding, returned by ::sfx_uplink_decode
 */
typedef enum _s_sfx_uld_err {
	/// no error occured, success
	SFX_ULD_ERR_NONE = 0,

	/// number of nibbles in message frame is even; only odd lengths can naturally occur
	SFX_ULD_ERR_FRAMELEN_EVEN,

	/// frame type doesn't match given messsage length
	SFX_ULD_ERR_FTYPE_MISMATCH,

	/// frame's CRC16 doesn't match CRC16 computed from frame contents
	SFX_ULD_ERR_CRC_INVALID,

	/// frame's MAC doesn't match MAC computed from frame contents (and private key); can only occur if `check_mac` parameter to ::sfx_uplink_decode is set
	SFX_ULD_ERR_MAC_INVALID,
} sfx_uld_err;

sfx_ule_err sfx_uplink_encode(sfx_ul_plain uplink, sfx_commoninfo common, sfx_ul_encoded *encoded);
sfx_uld_err sfx_uplink_decode(sfx_ul_encoded to_decode, sfx_ul_plain *uplink_out, sfx_commoninfo *common, bool check_mac);

#endif
