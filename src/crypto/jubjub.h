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

int ext_set_identity(extended_point_t *v);
int extn_set_identity(extended_niels_point_t *v);

int ext_double(extended_point_t *v);
int ext_add(extended_point_t *v, const extended_niels_point_t *a);
int ext_to_bytes(uint8_t *v, const extended_point_t *a);
int ext_from_bytes(extended_point_t *v, const uint8_t *a);

int ext_base_mult(extended_point_t *v, const extended_niels_point_t *base, fr_t *x);

int jubjub_hash(uint8_t *gd, const uint8_t *d, size_t len);

int jubjub_test(fq_t *r);
