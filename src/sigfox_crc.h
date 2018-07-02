#include <inttypes.h>

#ifndef _SIGFOX_CRC_H
#define _SIGFOX_CRC_H

uint16_t SIGFOX_CRC_crc16(uint8_t const data[], uint8_t length);
uint8_t SIGFOX_CRC_crc8(uint8_t const data[], uint8_t length);

#endif
