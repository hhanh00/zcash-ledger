#pragma once

#include "../types.h"

/// @brief PRF^expand(sk, t) := BLAKE2b-512("Zcash_ExpandSeed", sk || t)
/// @param key 
/// @param t 
void prf_expand_seed(uint8_t *key, uint8_t t);

