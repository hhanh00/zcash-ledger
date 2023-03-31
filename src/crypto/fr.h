#pragma once

#include <lcx_math.h>

#include "../types.h"

/// r = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7
static const uint8_t fr_m[32] = {
  0x0e, 0x7d, 0xb4, 0xea, 0x65, 0x33, 0xaf, 0xa9, 
  0x06, 0x67, 0x3b, 0x01, 0x01, 0x34, 0x3b, 0x00, 
  0xa6, 0x68, 0x20, 0x93, 0xcc, 0xc8, 0x10, 0x82, 
  0xd0, 0x97, 0x0e, 0x5e, 0xd6, 0xf7, 0x2c, 0xb7
};

/// q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
static const uint8_t fq_m[32] = {
  0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 
  0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05, 
  0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 
  0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01    
};

void swap_endian(uint8_t *data, int8_t len);
int fr_from_wide(uint8_t *data_512);

static inline int fq_square(fq_t *v) {
    uint8_t *_v = (uint8_t *)v;
    return cx_math_multm_no_throw(_v, _v, _v, fq_m, 32);
}

static inline int fq_double(fq_t *v) {
    uint8_t *_v = (uint8_t *)v;
    return cx_math_addm_no_throw(_v, _v, _v, fq_m, 32);
}

static inline int fq_add(fq_t *v, const fq_t *a, const fq_t *b) {
    return cx_math_addm_no_throw((uint8_t *)v, (uint8_t *)a, (uint8_t *)b, fq_m, 32);
}

static inline int fq_sub(fq_t *v, const fq_t *a, const fq_t *b) {
    return cx_math_subm_no_throw((uint8_t *)v, (uint8_t *)a, (uint8_t *)b, fq_m, 32);
}

static inline int fq_mult(fq_t *v, const fq_t *a, const fq_t *b) {
    return cx_math_multm_no_throw((uint8_t *)v, (uint8_t *)a, (uint8_t *)b, fq_m, 32);
}
