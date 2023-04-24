#pragma once

#include "../types.h"

void orchard_derive_spending_key(int8_t account);

int cmx(uint8_t *cmx, uint8_t *address, uint64_t value, uint8_t *rseed, uint8_t *rho);
