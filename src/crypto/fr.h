#pragma once

#include <lcx_math.h>

#include "../types.h"

/**
 * Work around an issue on the ST33K1M5 chip
 * Adding two numbers can result in a number greater than the modulus
 * We reduce it by subtracting 0
*/
#ifdef MOD_ADD_FIX
#define cx_bn_mod_add_fixed(a, b, c, m) cx_bn_mod_add(a, b, c, m); cx_bn_mod_sub(a, a, zero, m)
#else
#define cx_bn_mod_add_fixed(a, b, c, m) cx_bn_mod_add(a, b, c, m)
#endif

/// @brief Reverse bytes of data
/// @param data pointer to the beginning of the array
/// @param len length of the array
void swap_endian(uint8_t *data, int8_t len);

/// @brief Reverse each byte bit by bit (does not reverse the bytes themselves)
/// @param data pointer to the beginning of the array
/// @param len length of the array
void swap_bit_endian(uint8_t *data, int8_t len);

#ifdef TEST
void print_bn_internal(const char *label, cx_bn_t bn);
#define print_bn(label, bn) print_bn_internal(label, bn)
#else
#define print_bn(label, bn)
#endif

bool ff_is_zero(uint8_t *v);

#define BN_DEF(a) cx_bn_t a; CX_THROW(cx_bn_alloc(&a, 32));
#define BN_DEF_ZERO BN_DEF(zero); cx_bn_set_u32(zero, 0);

