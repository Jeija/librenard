#include <inttypes.h>

#ifndef _SIGFOX_HMAC_H
#define _SIGFOX_HMAC_H

int aes_128_cbc_encrypt(uint8_t *encrypted_data, uint8_t *data_to_encrypt, uint8_t data_len, uint8_t *key);

#endif
