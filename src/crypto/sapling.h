#pragma once

#include "../types.h"

/// @brief derive the expanded spending key
/// @param exp_sk 
void sapling_derive_spending_key(int8_t account);

/// @brief calculate the incoming viewing key
/// @param ivk 
/// @param ak 
/// @param nk 
void sapling_ivk(uint8_t *ivk, const uint8_t *ak, const uint8_t *nk);

int get_proofgen_key();

