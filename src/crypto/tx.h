#pragma once

#include <stddef.h>   // size_t
#include <stdbool.h>  // bool
#include <stdint.h>   // uint*_t

#include "../types.h"

// Signing function, users must have confirmed the tx
int sign_transparent(uint8_t *sighash);
int sign_sapling(uint8_t *sighash, uint8_t *alpha);
