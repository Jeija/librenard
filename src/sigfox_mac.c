#include <inttypes.h>

#include "ti_aes_128.h"

/* Source: https://github.com/pycom/pycom-micropython-censis/blob/master/esp32/sigfox/manufacturer_api.c */

int renard_aes_128_cbc_encrypt(uint8_t *encrypted_data, uint8_t *data_to_encrypt, uint8_t data_len, uint8_t *key)
{
	uint8_t i, j, blocks;
	uint8_t cbc[16] = { 0x00 };

	blocks = data_len / 16;
	for (i = 0; i < blocks; i++) {
		for (j = 0; j < 16; j++)
			cbc[j] ^= data_to_encrypt[j + i * 16];

		renard_aes_enc_dec(cbc, key, 0);

		for (j = 0; j < 16; j++)
			encrypted_data[j + (i * 16)] = cbc[j];
	}

	return 0;
}
