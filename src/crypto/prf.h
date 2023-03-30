#pragma once

#include "../types.h"

/// PRF^expand(sk, t) := BLAKE2b-512("Zcash_ExpandSeed", sk || t)
int prf_expand_seed(uint8_t *key, uint8_t t);
