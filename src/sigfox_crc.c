#include <stdint.h>

// Standard CRC-16-CCITT as implemented by the proprietary sigfox stack

#define CRC16_POLYNOMIAL 0x1021

uint16_t renard_crc16(uint8_t const data[], uint8_t length)
{
	if (length == 0)
		return 0;

	uint16_t remainder = 0;

	for (uint8_t i = 0; i < length; ++i) {
		remainder ^= (data[i] << 8);

		for (uint8_t bit = 8; bit > 0; --bit) {
			if (remainder & (1 << 15))
				remainder = ((remainder << 1) ^ CRC16_POLYNOMIAL);
			else
				remainder = (remainder << 1);
		}
	}

	return remainder;
}

// Standard CRC-8 8H2F as implemented by the proprietary sigfox stack

#define CRC8_POLYNOMIAL 0x2f

uint8_t renard_crc8(uint8_t const data[], uint8_t length)
{
	if (length == 0)
		return 0;

	uint8_t remainder = 0;

	for (uint8_t i = 0; i < length; ++i) {
		remainder ^= data[i];

		for (uint8_t bit = 8; bit > 0; --bit) {
			if (remainder & (1 << 7))
				remainder = ((remainder << 1) ^ CRC8_POLYNOMIAL);
			else
				remainder = (remainder << 1);
		}
	}

	return remainder;
}
