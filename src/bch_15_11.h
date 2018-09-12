#include <inttypes.h>
#include <stdbool.h>

#ifndef _BCH_15_11_H
#define _BCH_15_11_H

uint16_t bch_15_11_correct(uint16_t codeword, bool *changed);
uint16_t bch_15_11_extend(uint16_t message);

#endif
