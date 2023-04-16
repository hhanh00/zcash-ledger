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
#include <os.h>       // sprintf
#include <blake2s.h>

#include "fr.h"
#include "jubjub.h"

#include "globals.h"

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

void ext_set_identity(extended_point_t *v) {
    memset(v, 0, sizeof(extended_point_t));
    v->v[31] = 1;
    v->z[31] = 1;
}

void extn_set_identity(extended_niels_point_t *v) {
    memset(v, 0, sizeof(extended_niels_point_t));
    v->vpu[31] = 1;
    v->vmu[31] = 1;
    v->z[31] = 1;
}

void ext_to_niels(extended_niels_point_t *v, const extended_point_t *a) {
    fq_add(&v->vpu, &a->v, &a->u);
    fq_sub(&v->vmu, &a->v, &a->u);
    memmove(&v->z, &a->z, sizeof(fq_t));
    memmove(&v->t2d, fq_D2, 32);
    fq_mult(&v->t2d, &v->t2d, &a->t1);
    fq_mult(&v->t2d, &v->t2d, &a->t2);
}

void ext_double(extended_point_t *v) {
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
}

void ext_add(extended_point_t *x, const extended_niels_point_t *y) {
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
}

void ext_base_mult(extended_point_t *v, const extended_niels_point_t *base, fr_t *x) {
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
}

void ext_to_bytes(uint8_t *v, const extended_point_t *a) {
    fq_t zinv;
    memmove(&zinv, &a->z, 32);
    fq_inv(&zinv);

    fq_t u;
    fq_mult(&u, &a->u, &zinv);
    fq_mult((fq_t *)v, &a->v, &zinv);

    uint8_t sign = u[31] & 1;
    v[0] |= sign << 7;

    swap_endian(v, 32);
}

void ext_to_u(uint8_t *u, const extended_point_t *a) {
    fq_t zinv;
    memmove(&zinv, &a->z, 32);
    fq_inv(&zinv);

    fq_mult((fq_t *)u, &a->u, &zinv);
    swap_endian(u, 32);
}

int extn_from_bytes(extended_niels_point_t *r, const uint8_t *v0) {
    int error = 0;
    fq_t v;
    memmove(&v, v0, 32);

    uint8_t *pv = (uint8_t *)&v;

    uint8_t sign = pv[31] >> 7;
    pv[31] &= 0x7F;
    swap_endian(pv, 32);

    if (!fq_ok(&v)) return CX_INVALID_PARAMETER;

    fq_t v2;
    memmove(&v2, v, 32);
    fq_square(&v2);

    fq_t v2m1;
    fq_sub(&v2m1, &v2, &fq_1); // v2-1

    fq_mult(&v2, &v2, &fq_D); //v2*D
    fq_add(&v2, &v2, &fq_1); //v2*D+1
    fq_inv(&v2); // 1/(v2*D+1)
    fq_mult(&v2, &v2m1, &v2); // v2 = (v2-1)/(v2*D+1)

    cx_bn_lock(32, 0);
    cx_bn_t u2, m, bn_u;
    cx_bn_alloc_init(&u2, 32, (uint8_t *)&v2, 32);
    cx_bn_alloc_init(&m, 32, (uint8_t *)&fq_m, 32);
    cx_bn_alloc(&bn_u, 32);

    error = cx_bn_mod_sqrt(bn_u, u2, m, sign);

    fq_t u;
    cx_bn_export(bn_u, (uint8_t *)&u, 32);
    cx_bn_unlock();

    if (error) return error;

    extended_point_t p;

    memmove(&p.u, &u, 32);
    memmove(&p.v, &v, 32);
    memmove(&p.z, &fq_1, 32);
    memmove(&p.t1, &u, 32);
    memmove(&p.t2, &v, 32);
    
    ext_double(&p);
    ext_double(&p);
    ext_double(&p); // * by cofactor

    fq_add(&r->vpu, &p.v, &p.u); // Reuse to_niels?
    fq_sub(&r->vmu, &p.v, &p.u);
    memmove(&r->z, &p.z, 32);
    memmove(&r->t2d, fq_D2, 32);
    fq_mult(&r->t2d, &r->t2d, &p.t1);
    fq_mult(&r->t2d, &r->t2d, &p.t2);

    return 0;
}

void jubjub_hash(uint8_t *gd, const uint8_t *d, size_t len) {
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
}

void jubjub_to_pk(uint8_t *pk, const extended_niels_point_t *gen, fr_t *sk) {
    extended_point_t temp;
    ext_base_mult(&temp, gen, sk);
    ext_to_bytes(pk, &temp);
    PRINTF("SK: %.*H\n", 32, sk);
    PRINTF("PK: %.*H\n", 32, pk);
}

int h_star(uint8_t *hash, uint8_t *data, size_t len) {
    cx_blake2b_t hasher;
    cx_blake2b_init2_no_throw(&hasher, 512,
                              NULL, 0, (uint8_t *) "Zcash_RedJubjubH", 16);
    cx_hash((cx_hash_t *)&hasher, CX_LAST, data, len, hash, 64);
    fr_from_wide(hash);

    return 0;
}

int sign(uint8_t *signature, fr_t *sk, uint8_t *message) {
    uint8_t buffer[144];
    memset(buffer, 0, sizeof(buffer));

    // cx_get_random_bytes(buffer, 80); // TODO: Put it back
    memmove(buffer + 80, message, 64);

    uint8_t r_buffer[64]; // we need 64 bytes but only the first 32 will be used as a return value
    h_star(r_buffer, buffer, 144);

    fr_t r;
    memmove(&r, r_buffer, 32);
    a_to_pk(signature, &r); // R = r.G

    memmove(buffer, signature, 32);
    memmove(buffer + 32, message, 64);
    h_star(r_buffer, buffer, 96);
    fr_t *S = (fr_t *)(signature + 32);
    memmove(S, r_buffer, 32);

    fr_mult(S, S, sk);
    fr_add(S, S, &r); // S = r + H*(Rbar || M) . sk
    swap_endian(signature + 32, 32);

    return 0;
}
