#pragma once

#include <lcx_math.h>

#include "../types.h"

/**
 * Work around an issue on the ST33K1M5 chip
 * Adding two numbers can result in a number greater than the modulus
 * We reduce it by subtracting 0
*/
#ifndef MOD_ADD_FIX
#define cx_bn_mod_add_fixed(a, b, c, m) cx_bn_mod_add(a, b, c, m); cx_bn_mod_sub(a, a, zero, m)
#else
#define cx_bn_mod_add_fixed(a, b, c, m) cx_bn_mod_add(a, b, c, m)
#endif

/// Modulus of Pasta base field
/// p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
static const uint8_t fp_m[32] = {
  0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x22, 0x46, 0x98, 0xfc, 0x09, 0x4c, 0xf9, 0x1b, 
  0x99, 0x2d, 0x30, 0xed, 0x00, 0x00, 0x00, 0x01,
};

/// Modulus of Pasta scalar field
/// v = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
static const uint8_t fv_m[32] = {
  0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x22, 0x46, 0x98, 0xfc, 0x09, 0x94, 0xa8, 0xdd, 
  0x8c, 0x46, 0xeb, 0x21, 0x00, 0x00, 0x00, 0x01,
};

/// @brief Reverse bytes of data
/// @param data pointer to the beginning of the array
/// @param len length of the array
void swap_endian(uint8_t *data, int8_t len);

/// @brief Reverse each byte bit by bit (does not reverse the bytes themselves)
/// @param data pointer to the beginning of the array
/// @param len length of the array
void swap_bit_endian(uint8_t *data, int8_t len);

/// @brief Convert a 512 bit Little Endian number into Fr
/// @param data_512 pointer to the beginning of the data
void fr_from_wide(uint8_t *data_512);

/// @brief Convert a 512 bit Little Endian number into Fv
/// @param data_512 pointer to the beginning of the data
void fv_from_wide(uint8_t *data_512);
void fv_from_wide_be(uint8_t *data_512);

void fp_from_wide(uint8_t *data_512);
void fp_from_wide_be(uint8_t *data_512);

static inline bool fp_ok(fq_t *v) {
    int diff;
    cx_math_cmp_no_throw((uint8_t *)v, fp_m, 32, &diff);
    return diff < 0;
}

static inline void fv_negate(fv_t *v) {
    fv_t zero;
    memset(&zero, 0, 32);
    cx_math_subm_no_throw((uint8_t *)v, (uint8_t *)zero, (uint8_t *)v, fv_m, 32);
}

static inline void fv_add(fv_t *v, const fv_t *a, const fv_t *b) {
    cx_math_addm_no_throw((uint8_t *)v, (uint8_t *)a, (uint8_t *)b, fv_m, 32);
}

static inline void fv_mult(fv_t *v, const fv_t *a, const fv_t *b) {
    cx_math_multm_no_throw((uint8_t *)v, (uint8_t *)a, (uint8_t *)b, fv_m, 32);
}

#ifdef TEST
void print_bn_internal(const char *label, cx_bn_t bn);
#define print_bn(label, bn) print_bn_internal(label, bn)
#else
#define print_bn(label, bn)
#endif

bool ff_is_zero(uint8_t *v);

#define BN_DEF(a) cx_bn_t a; cx_bn_alloc(&a, 32);
#define BN_DEF_ZERO BN_DEF(zero); cx_bn_set_u32(zero, 0);

