#pragma once

#include "../types.h"

/// @brief PRF^expand(sk, t) := BLAKE2b-512("Zcash_ExpandSeed", sk || t)
/// @param key 
/// @param t 
void prf_expand_seed(uint8_t *key, uint8_t t);

void prf_expand_seed_with_ad(uint8_t *key, uint8_t t, uint8_t *ad, size_t ad_len);
