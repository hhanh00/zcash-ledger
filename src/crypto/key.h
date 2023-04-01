#pragma once

#include "../types.h"

int crypto_derive_spending_key(expanded_spending_key_t *exp_sk);
int calc_ivk(uint8_t *ivk, const uint8_t *ak, const uint8_t *nk);