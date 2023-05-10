#pragma once

#include "../types.h"

/**
 * FPE FF1-AES256 specialized for radix = 2 and data size = 11 bytes
 * 
 * Used to map from diversifier index to diversifier value
 * 
 * @in dk: 32-byte diversifier key 
 * @in di: 11-byte diversifier index
 * @out d: 11-byte diversifier value
 * 
 * cannot throw/error
*/
void ff1_inplace(const uint8_t *dk, uint8_t *di);
