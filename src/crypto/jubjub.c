/*****************************************************************************
 *   Zcash Ledger App.
 *   (c) 2022 Hanh Huynh Huu.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>   // uint*_t
#include <string.h>   // memset, explicit_bzero
#include <stdbool.h>  // bool
#include <blake2s.h>

#include "fr.h"
#include "jubjub.h"

#include "globals.h"

static const extended_point_t SPENDING_GENERATOR = {
    .u =
        {
            0x09, 0x26, 0xD4, 0xF3, 0x20, 0x59, 0xC7, 0x12, 0xD4, 0x18, 0xA7,
            0xFF, 0x26, 0x75, 0x3B, 0x6A, 0xD5, 0xB9, 0xA7, 0xD3, 0xEF, 0x8E,
            0x28, 0x27, 0x47, 0xBF, 0x46, 0x92, 0x0A, 0x95, 0xA7, 0x53,
        },
    .v =
        {
            0x57, 0xA1, 0x01, 0x9E, 0x6D, 0xE9, 0xB6, 0x75, 0x53, 0xBB, 0x37,
            0xD0, 0xC2, 0x1C, 0xFD, 0x05, 0x6D, 0x65, 0x67, 0x4D, 0xCE, 0xDB,
            0xDD, 0xBC, 0x30, 0x56, 0x32, 0xAD, 0xAA, 0xF2, 0xB5, 0x30,
        },
    .z =
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        },
    .t1 =
        {
            0x09, 0x26, 0xD4, 0xF3, 0x20, 0x59, 0xC7, 0x12, 0xD4, 0x18, 0xA7,
            0xFF, 0x26, 0x75, 0x3B, 0x6A, 0xD5, 0xB9, 0xA7, 0xD3, 0xEF, 0x8E,
            0x28, 0x27, 0x47, 0xBF, 0x46, 0x92, 0x0A, 0x95, 0xA7, 0x53,
        },
    .t2 =
        {
            0x57, 0xA1, 0x01, 0x9E, 0x6D, 0xE9, 0xB6, 0x75, 0x53, 0xBB, 0x37,
            0xD0, 0xC2, 0x1C, 0xFD, 0x05, 0x6D, 0x65, 0x67, 0x4D, 0xCE, 0xDB,
            0xDD, 0xBC, 0x30, 0x56, 0x32, 0xAD, 0xAA, 0xF2, 0xB5, 0x30,
        },
};

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

static const extended_niels_point_t IDENTITY_NIELS = {
    .vpu =
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        },
    .vmu =
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        },
    .z =
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        },
    .t2d =
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        },
};

int ext_set_identity(extended_point_t *v) {
    memset(v, 0, sizeof(extended_point_t));
    v->v[31] = 1;
    v->z[31] = 1;
    return 0;
}

int extn_set_identity(extended_niels_point_t *v) {
    memset(v, 0, sizeof(extended_point_t));
    v->vpu[31] = 1;
    v->vmu[31] = 1;
    v->z[31] = 1;
    return 0;
}


int ext_double(extended_point_t *v) {
    fq_t uu;
    memmove(&uu, &v->u, 32);
    fq_square(&uu);

    fq_t vv;
    memmove(&vv, &v->v, 32);
    fq_square(&vv);

    fq_t zz2;
    memmove(&zz2, &v->z, 32);
    fq_square(&zz2);
    fq_double(&zz2);

    fq_t uv2;
    fq_add(&uv2, &v->u, &v->v);
    fq_square(&uv2);

    fq_t vpu;
    fq_add(&vpu, &vv, &uu);

    fq_t vmu;
    fq_sub(&vmu, &vv, &uu);

    fq_t t;
    fq_sub(&t, &zz2, &vmu);

    fq_sub(&v->t1, &uv2, &vpu);
    memmove(&v->t2, &vpu, 32);
    fq_mult(&v->u, &v->t1, &t);
    fq_mult(&v->v, &v->t2, &vmu);
    fq_mult(&v->z, &vmu, &t);

    return 0;
}

int ext_add(extended_point_t *x, const extended_niels_point_t *y) {
    fq_t a;
    fq_t b;
    fq_sub(&a, &x->v, &x->u);
    fq_mult(&a, &a, &y->vmu);
    fq_add(&b, &x->v, &x->u);
    fq_mult(&b, &b, &y->vpu);

    fq_t u;
    fq_t v;
    fq_sub(&u, &b, &a);
    fq_add(&v, &b, &a);

    fq_mult(&a, &x->t1, &x->t2);
    fq_mult(&a, &a, &y->t2d);
    fq_mult(&b, &x->z, &y->z);
    fq_double(&b);

    memmove(&x->t1, &u, 32);
    memmove(&x->t2, &v, 32);

    fq_add(&u, &b, &a);
    fq_sub(&v, &b, &a);

    fq_mult(&x->u, &x->t1, &v);
    fq_mult(&x->v, &x->t2, &u);
    fq_mult(&x->z, &u, &v);

    return 0;
}

int ext_base_mult(extended_point_t *v, const extended_niels_point_t *base, fr_t *x) {
    ext_set_identity(v);

    int j0 = 4; // skip highest 4 bits (always set to 0 for Fr)
    for (int i = 0; i < 32; i++) {
        uint8_t c = (*x)[i];
        for (int j = j0; j < 8; j++) {
            ext_double(v);
            if (((c >> (7-j)) & 1) != 0) {
                ext_add(v, base);
            }
            else {
                ext_add(v, &IDENTITY_NIELS);
            }
        }
        j0 = 0;
    }
    return 0;
}

int ext_to_bytes(uint8_t *v, const extended_point_t *a) {
    fq_t zinv;
    memmove(&zinv, &a->z, 32);
    fq_inv(&zinv);

    fq_t u;
    fq_mult(&u, &a->u, &zinv);
    fq_mult((fq_t *)v, &a->v, &zinv);

    uint8_t sign = u[31] & 1;
    v[0] |= sign << 7;

    swap_endian(v, 32);
    return 0;
}

int ext_from_bytes(extended_point_t *v, const uint8_t *a) {
    int error = 0;
    fq_t b;
    memmove(&b, a, 32);

    uint8_t *pb = (uint8_t *)&b;

    uint8_t sign = pb[31] >> 7;
    pb[31] &= 0x7F;
    swap_endian(pb, 32);

    if (!fq_ok(&b)) return CX_INVALID_PARAMETER;

    fq_square(&b);

    fq_t b2;
    memmove(&b2, b, 32);

    fq_sub(&b, &b, &fq_1); // v2-1

    fq_mult(&b2, &b2, &fq_D); //v2*D
    fq_add(&b2, &b2, &fq_1); //v2*D+1
    fq_inv(&b2); // 1/(v2*D+1)
    fq_mult(&b, &b, &b2); // (v2-1)/(v2*D+1)

    cx_bn_lock(32, 0);
    cx_bn_t u2, m, bn_u;
    cx_bn_alloc_init(&u2, 32, (uint8_t *)&b, 32);
    cx_bn_alloc_init(&m, 32, (uint8_t *)&fq_m, 32);
    cx_bn_alloc(&bn_u, 32);

    error = cx_bn_mod_sqrt(bn_u, u2, m, 1);

    fq_t u;
    cx_bn_export(bn_u, (uint8_t *)&u, 32);
    cx_bn_unlock();

    if (error) return error;

    bool flip_sign = (u[31] ^ sign) != 0;
    if (flip_sign)
        fq_neg(&u);

    ext_set_identity(v);
    memmove(&v->u, &u, 32);
    memmove(&v->v, &v, 32);

    return 0;
}

int jubjub_hash(uint8_t *gd, const uint8_t *d, size_t len) {
    int error = 0;

    blake2s_state hash_ctx;
    blake2s_param hash_params;
    memset(&hash_params, 0, sizeof(hash_params));
    hash_params.digest_length = 32;
    hash_params.fanout = 1;
    hash_params.depth = 1;
    memmove(&hash_params.personal, "Zcash_gd", 8);

    blake2s_init_param(&hash_ctx, &hash_params);
    blake2s_update(&hash_ctx, "096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0", 64);
    blake2s_update(&hash_ctx, d, len);
    blake2s_final(&hash_ctx, gd, 32);

    return error;
}



int jubjub_test(fq_t *r) {
    extended_point_t v;

    ext_base_mult(&v, &SPENDING_GENERATOR_NIELS, r);
    ext_to_bytes((uint8_t *)r, &v);
    return 0;
}
