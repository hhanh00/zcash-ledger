#pragma once

#include "../types.h"

typedef struct {
    fq_t u;
    fq_t v;
} affine_point_t;

typedef struct {
    fq_t u;
    fq_t v;
    fq_t z;
    fq_t t1;
    fq_t t2;
} extended_point_t;

typedef struct {
    fq_t vpu;
    fq_t vmu;
    fq_t z;
    fq_t t2d;
} extended_niels_point_t;

static const extended_niels_point_t SPENDING_GENERATOR_NIELS = {
    .vpu =
        {
            0x60, 0xC7, 0xD6, 0x91, 0x8E, 0x43, 0x7D, 0x88, 0x27, 0xD3, 0xDF,
            0xCF, 0xE8, 0x92, 0x38, 0x70, 0x43, 0x1F, 0x0F, 0x21, 0xBE, 0x6A,
            0x05, 0xE3, 0x78, 0x15, 0x79, 0x3F, 0xB5, 0x88, 0x5C, 0x83,
        },
    .vmu =
        {
            0x4E, 0x7A, 0x2C, 0xAB, 0x4D, 0x8F, 0xEF, 0x62, 0x7F, 0xA2, 0x8F,
            0xD1, 0x9B, 0xA7, 0xC1, 0x9A, 0x97, 0xAB, 0xBF, 0x79, 0xDF, 0x4D,
            0xB5, 0x94, 0xE8, 0x96, 0xEC, 0x1B, 0xA0, 0x5D, 0x0D, 0xDD,
        },
    .z =
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        },
    .t2d =
        {
            0x2A, 0xB8, 0xC1, 0x5A, 0x55, 0x5F, 0x87, 0x63, 0xBE, 0x33, 0xBD,
            0x80, 0x2D, 0xC5, 0xB5, 0x95, 0x7B, 0x5E, 0xDB, 0x80, 0x18, 0xB4,
            0xF8, 0x1F, 0xCB, 0x6A, 0xCE, 0xF9, 0x5B, 0x05, 0x8A, 0x6B,
        },
};

static const extended_niels_point_t PROOF_GENERATOR_NIELS = {
    .vpu =
        {
            0x69, 0x0E, 0x76, 0x09, 0x4A, 0xAD, 0x0D, 0x5A, 0x4F, 0x0C, 0x05,
            0x75, 0xF7, 0xD9, 0xA9, 0x4D, 0xFE, 0xD2, 0x22, 0x23, 0xE8, 0x9D,
            0x01, 0xF2, 0x81, 0x6D, 0xD5, 0xE7, 0x99, 0xCC, 0x0E, 0x58,
        },
    .vmu =
        {
            0x40, 0x5F, 0x2C, 0x04, 0xE7, 0x11, 0x47, 0x9B, 0x6E, 0x85, 0xFD,
            0x92, 0x26, 0xB8, 0xE8, 0x4A, 0xA2, 0xEC, 0x81, 0xB2, 0x02, 0xA5,
            0x91, 0xB2, 0x0B, 0x88, 0x1E, 0x08, 0x26, 0xEF, 0xC3, 0x76,
        },
    .z =
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        },
    .t2d =
        {
            0x56, 0xF7, 0x9F, 0x1B, 0xF5, 0x6A, 0x37, 0x96, 0xF9, 0xF8, 0xBA,
            0x5D, 0x92, 0x6C, 0x61, 0x23, 0x9A, 0x1F, 0x8B, 0x0B, 0x25, 0x6E,
            0x74, 0x8A, 0xDD, 0x79, 0x02, 0xCD, 0x81, 0x22, 0x33, 0x7C,
        },
};

int ext_set_identity(extended_point_t *v);
int extn_set_identity(extended_niels_point_t *v);

int ext_double(extended_point_t *v);
int ext_add(extended_point_t *v, const extended_niels_point_t *a);
int ext_to_bytes(uint8_t *v, const extended_point_t *a);
int extn_from_bytes(extended_niels_point_t *v, const uint8_t *a);

int ext_base_mult(extended_point_t *v, const extended_niels_point_t *base, fr_t *x);

int jubjub_hash(uint8_t *gd, const uint8_t *d, size_t len);

int jubjub_to_pk(uint8_t *pk, const extended_niels_point_t *gen, fr_t *sk);

static inline int a_to_pk(uint8_t *ak, fr_t *ask) {
    return jubjub_to_pk(ak, &SPENDING_GENERATOR_NIELS, ask);
}

static inline int n_to_pk(uint8_t *nk, fr_t *nsk) {
    return jubjub_to_pk(nk, &PROOF_GENERATOR_NIELS, nsk);
}

int jubjub_test(fq_t *r);
