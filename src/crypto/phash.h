#pragma once

#include "fr.h"

int calc_cmu(uint8_t *cmu, uint8_t *address, uint8_t *rseed, uint64_t value);
void pedersen_hash_cmu(uint8_t *cmu, uint64_t value, uint8_t *g_d, uint8_t *pk_d, fr_t *rcm);
