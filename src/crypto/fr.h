#pragma once

#include <lcx_math.h>

#include "../types.h"

/**
 * Work around an issue on the ST33K1M5 chip
 * Adding two numbers can result in a number greater than the modulus
 * We reduce it by subtracting 0
*/
// #ifndef ST33K1M5
// #define cx_bn_mod_add_fixed(a, b, c, m) cx_bn_mod_add(a, b, c, m)
// #else
// #define cx_bn_mod_add_fixed(a, b, c, m) cx_bn_mod_add(a, b, c, m); cx_bn_mod_sub(a, a, zero, m)
// #endif

#define cx_bn_mod_add_fixed(a, b, c, m) cx_bn_mod_add(a, b, c, m); cx_bn_mod_sub(a, a, zero, m)

/**
 * Fr is the finite field (FF) for the Jubjub (JJ) point multiplicative group
 * Fq is the FF for the coordinates of points on JJ
*/

/// r is the modulus of Fr
/// r = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7
static const uint8_t fr_m[32] = {
  0x0e, 0x7d, 0xb4, 0xea, 0x65, 0x33, 0xaf, 0xa9, 
  0x06, 0x67, 0x3b, 0x01, 0x01, 0x34, 0x3b, 0x00, 
  0xa6, 0x68, 0x20, 0x93, 0xcc, 0xc8, 0x10, 0x82, 
  0xd0, 0x97, 0x0e, 0x5e, 0xd6, 0xf7, 0x2c, 0xb7
};

/// q is the modulus of Fq
/// q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
static const uint8_t fq_m[32] = {
  0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 
  0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05, 
  0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 
  0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01    
};

/// 0 in Fq
static const uint8_t fq_0[32] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
};

/// 1 in Fq
static const uint8_t fq_1[32] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
};

/// the parameter d of JJ in Fq
/// JJ is a twisted Edward curve: -u^2 + v^2 = 1 + d.u^2.v^2
static const uint8_t fq_D[32] = {
  0x2A, 0x93, 0x18, 0xE7, 0x4B, 0xFA, 0x2B, 0x48, 
  0xF5, 0xFD, 0x92, 0x07, 0xE6, 0xBD, 0x7F, 0xD4, 
  0x29, 0x2D, 0x7F, 0x6D, 0x37, 0x57, 0x9D, 0x26, 
  0x01, 0x06, 0x5F, 0xD6, 0xD6, 0x34, 0x3E, 0xB1,
};

/// 2*d in Fq
static const uint8_t fq_D2[32] = {
  0x55, 0x26, 0x31, 0xCE, 0x97, 0xF4, 0x56, 0x91, 
  0xEB, 0xFB, 0x24, 0x0F, 0xCD, 0x7A, 0xFF, 0xA8, 
  0x52, 0x5A, 0xFE, 0xDA, 0x6E, 0xAF, 0x3A, 0x4C, 
  0x02, 0x0C, 0xBF, 0xAD, 0xAC, 0x68, 0x7D, 0x62,
};

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

/// @brief v*v -> v
/// @param v 
static inline void fq_square(fq_t *v) {
    uint8_t *_v = (uint8_t *)v;
    cx_math_multm_no_throw(_v, _v, _v, fq_m, 32);
}

/// @brief 2*v -> v
/// @param v 
static inline void fq_double(fq_t *v) {
    uint8_t *_v = (uint8_t *)v;
    cx_math_addm_no_throw(_v, _v, _v, fq_m, 32);
}

/// @brief a + b -> v
/// @param v 
/// @param a 
/// @param b 
static inline void fq_add(fq_t *v, const fq_t *a, const fq_t *b) {
    cx_math_addm_no_throw((uint8_t *)v, (uint8_t *)a, (uint8_t *)b, fq_m, 32);
}

/// @brief a - b -> v
/// @param v 
/// @param a 
/// @param b 
static inline void fq_sub(fq_t *v, const fq_t *a, const fq_t *b) {
    cx_math_subm_no_throw((uint8_t *)v, (uint8_t *)a, (uint8_t *)b, fq_m, 32);
}

/// @brief -v -> v
/// @param v 
static inline void fq_neg(fq_t *v) {
    fq_t zero;
    memset(&zero, 0, 32);
    cx_math_subm_no_throw((uint8_t *)v, (uint8_t *)zero, (uint8_t *)v, fq_m, 32);
}

/// @brief a * b -> v
/// @param v 
/// @param a 
/// @param b 
static inline void fq_mult(fq_t *v, const fq_t *a, const fq_t *b) {
    cx_math_multm_no_throw((uint8_t *)v, (uint8_t *)a, (uint8_t *)b, fq_m, 32);
}

/// @brief 1/v -> v
/// @param v 
static inline void fq_inv(fq_t *v) {
    cx_math_invprimem_no_throw((uint8_t *)v, (uint8_t *)v, fq_m, 32);
}

/// @brief check if v has low order, v < fq_m
/// @param v 
/// @return true if ok
static inline bool fq_ok(fq_t *v) {
    int diff;
    cx_math_cmp_no_throw((uint8_t *)v, fq_m, 32, &diff);
    return diff < 0;
}

/// @brief a + b -> v
/// @param v 
/// @param a 
/// @param b 
static inline void fr_add(fr_t *v, const fr_t *a, const fr_t *b) {
    cx_math_addm_no_throw((uint8_t *)v, (uint8_t *)a, (uint8_t *)b, fr_m, 32);
}

static inline void fr_double(fr_t *v) {
    cx_math_addm_no_throw((uint8_t *)v, (uint8_t *)v, (uint8_t *)v, fr_m, 32);
}

static inline void fr_negate(fr_t *v) {
    fr_t zero;
    memset(&zero, 0, 32);
    cx_math_subm_no_throw((uint8_t *)v, (uint8_t *)zero, (uint8_t *)v, fr_m, 32);
}

static inline void fr_mult(fr_t *v, const fr_t *a, const fr_t *b) {
    cx_math_multm_no_throw((uint8_t *)v, (uint8_t *)a, (uint8_t *)b, fr_m, 32);
}

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

void print_bn(const char *label, cx_bn_t bn);

bool ff_is_zero(uint8_t *v);
