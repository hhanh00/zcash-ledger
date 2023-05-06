#pragma once

#include "fr.h"

/// @brief Calculate the Sapling note commitment
/// @param cmu Note commitment, 32 bytes
/// @param address Destination address, 43 bytes: 11 (d) + 32 (pk_d)
/// @param rseed Random seed, 32 bytes
/// @param value Note value in zats, 8 bytes
/// @return 
int calc_cmu(uint8_t *cmu, uint8_t *address, uint8_t *rseed, uint64_t *value);

/// @brief Pedersen Hash Commitment
/// @param cmu Returned note commitment, 32 bytes
/// @param value Note value
/// @param g_d Generator point (computed from d)
/// @param pk_d Address public key
/// @param rcm derived from rseed
void pedersen_hash_cmu(uint8_t *cmu, uint64_t *value, uint8_t *g_d, uint8_t *pk_d, fr_t *rcm);
