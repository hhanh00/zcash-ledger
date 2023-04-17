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
#include <ox_bn.h>
#include <blake2s.h>

#include "fr.h"
#include "jubjub.h"

#include "globals.h"

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

typedef struct {
    cx_bn_t u;
    cx_bn_t v;
    cx_bn_t z;
    cx_bn_t t1;
    cx_bn_t t2;
} bn_extended_point_t;

typedef struct {
    cx_bn_t vpu;
    cx_bn_t vmu;
    cx_bn_t z;
    cx_bn_t t2d;
} bn_extended_niels_point_t;

static void print_bn(const char *label, cx_bn_t bn) {
    uint8_t v[32];
    cx_bn_export(bn, v, 32);
    PRINTF(">> %s %.*H\n", label, 32, v);
}

void bn_init_identity(bn_extended_point_t *v, cx_bn_mont_ctx_t *ctx) {
    cx_bn_alloc_init(&v->u, 32, fq_0, 32);
    cx_bn_alloc_init(&v->v, 32, fq_1, 32);
    cx_bn_alloc_init(&v->z, 32, fq_1, 32);
    cx_bn_alloc_init(&v->t1, 32, fq_0, 32);
    cx_bn_alloc_init(&v->t2, 32, fq_0, 32);
    #ifndef DEBUG
    cx_mont_to_montgomery(v->v, v->v, ctx);
    cx_mont_to_montgomery(v->z, v->z, ctx);
    #endif
}

void bn_load_extended_niels(bn_extended_niels_point_t *v, const extended_niels_point_t *a,
        cx_bn_mont_ctx_t *ctx) {
    cx_bn_alloc_init(&v->vpu, 32, a->vpu, 32);
    cx_bn_alloc_init(&v->vmu, 32, a->vmu, 32);
    cx_bn_alloc_init(&v->z, 32, a->z, 32);
    cx_bn_alloc_init(&v->t2d, 32, a->t2d, 32);
    #ifndef DEBUG
    cx_mont_to_montgomery(v->vpu, v->vpu, ctx);
    cx_mont_to_montgomery(v->vmu, v->vmu, ctx);
    cx_mont_to_montgomery(v->z, v->z, ctx);
    cx_mont_to_montgomery(v->t2d, v->t2d, ctx);
    #endif
}

void bn_store_extended(extended_point_t *v, const bn_extended_point_t *a, cx_bn_mont_ctx_t *ctx) {
    #ifndef DEBUG
    cx_mont_from_montgomery(a->u, a->u, ctx);
    cx_mont_from_montgomery(a->v, a->v, ctx);
    cx_mont_from_montgomery(a->z, a->z, ctx);
    cx_mont_from_montgomery(a->t1, a->t1, ctx);
    cx_mont_from_montgomery(a->t2, a->t2, ctx);
    #endif
    cx_bn_export(a->u, v->u, 32);
    cx_bn_export(a->v, v->v, 32);
    cx_bn_export(a->z, v->z, 32);
    cx_bn_export(a->t1, v->t1, 32);
    cx_bn_export(a->t2, v->t2, 32);
}

#ifdef DEBUG
#define CX_MUL(r, a, b) cx_bn_mod_mul(r, a, b, q_m)
#else
#define CX_MUL(r, a, b) cx_mont_mul(r, a, b, ctx)
#endif

static void bn_ext_double(bn_extended_point_t *v, cx_bn_t q_m, cx_bn_mont_ctx_t *ctx) {
    cx_bn_t temp;
    cx_bn_alloc(&temp, 32);
    cx_bn_t uu;
    cx_bn_alloc(&uu, 32);
    cx_bn_copy(uu, v->u);
    CX_MUL(temp, uu, uu);
    cx_bn_copy(uu, temp);

    cx_bn_t vv;
    cx_bn_alloc(&vv, 32);
    cx_bn_copy(vv, v->v);
    CX_MUL(temp, vv, vv);
    cx_bn_copy(vv, temp);

    cx_bn_t zz2;
    cx_bn_alloc(&zz2, 32);
    cx_bn_copy(zz2, v->z);
    CX_MUL(temp, zz2, zz2);
    cx_bn_copy(zz2, temp);
    cx_bn_mod_add(zz2, zz2, zz2, q_m);

    cx_bn_t uv2;
    cx_bn_alloc(&uv2, 32);
    
    cx_bn_mod_add(uv2, v->u, v->v, q_m);
    CX_MUL(temp, uv2, uv2);
    cx_bn_copy(uv2, temp);

    cx_bn_t vpu;
    cx_bn_alloc(&vpu, 32);
    cx_bn_mod_add(vpu, vv, uu, q_m); // vpu = v*v + u*u

    cx_bn_t vmu;
    cx_bn_alloc(&vmu, 32);
    cx_bn_mod_sub(vmu, vv, uu, q_m); // vmu = v*v - u*u

    cx_bn_t t;
    cx_bn_alloc(&t, 32);
    cx_bn_mod_sub(t, zz2, vmu, q_m);

    cx_bn_mod_sub(v->t1, uv2, vpu, q_m);
    cx_bn_copy(v->t2, vpu);
    CX_MUL(v->u, v->t1, t);
    CX_MUL(v->v, v->t2, vmu);
    CX_MUL(v->z, vmu, t);

    cx_bn_destroy(&temp);
    cx_bn_destroy(&t);
    cx_bn_destroy(&vmu);
    cx_bn_destroy(&vpu);
    cx_bn_destroy(&uv2);
    cx_bn_destroy(&zz2);
    cx_bn_destroy(&vv);
    cx_bn_destroy(&uu);
}

static void bn_ext_add(bn_extended_point_t *x, const bn_extended_niels_point_t *y, cx_bn_t q_m,
        cx_bn_mont_ctx_t *ctx) {
    cx_bn_t temp; cx_bn_alloc(&temp, 32);
    cx_bn_t a; cx_bn_alloc(&a, 32);
    cx_bn_t b; cx_bn_alloc(&b, 32);
    cx_bn_mod_sub(a, x->v, x->u, q_m); // a = (v - u) * vmu
    CX_MUL(temp, a, y->vmu);
    cx_bn_copy(a, temp);
    cx_bn_mod_add(b, x->v, x->u, q_m); // b = (v + u) * vpu
    CX_MUL(temp, b, y->vpu);
    cx_bn_copy(b, temp);

    cx_bn_t c; cx_bn_alloc(&c, 32);
    cx_bn_t d; cx_bn_alloc(&d, 32);
    CX_MUL(temp, x->t1, x->t2); 
    CX_MUL(c, temp, y->t2d); // c = t1 * t2 * t2d
    CX_MUL(d, x->z, y->z);
    cx_bn_mod_add(d, d, d, q_m); // d = 2zz

    cx_bn_t u; cx_bn_alloc(&u, 32);
    cx_bn_t v; cx_bn_alloc(&v, 32);
    cx_bn_mod_sub(u, b, a, q_m); // u = b - a
    cx_bn_mod_add(v, b, a, q_m); // v = b + a

    cx_bn_t z; cx_bn_alloc(&z, 32);
    cx_bn_t t; cx_bn_alloc(&t, 32);
    cx_bn_mod_add(z, d, c, q_m); // z = d + c
    cx_bn_mod_sub(t, d, c, q_m); // t = d - c

    // print_bn("A", a);
    // print_bn("B", b);
    // print_bn("C", c);
    // print_bn("D", d);
    // print_bn("U", u);
    // print_bn("V", v);
    // print_bn("Z", z);
    // print_bn("T", t);

    cx_bn_destroy(&a);
    cx_bn_destroy(&b);
    cx_bn_destroy(&c);
    cx_bn_destroy(&d);

    CX_MUL(x->u, u, t); // u = ut
    CX_MUL(x->v, v, z); // v = vz
    CX_MUL(x->z, z, t); // z = zt
    cx_bn_copy(x->t1, u); // t1 = u
    cx_bn_copy(x->t2, v); // t2 = v

    cx_bn_destroy(&u);
    cx_bn_destroy(&v);
    cx_bn_destroy(&z);
    cx_bn_destroy(&t);
    cx_bn_destroy(&temp);
}

void ext_base_mult(extended_point_t *v, const extended_niels_point_t *base, fr_t *x) {
    cx_bn_lock(32, 0);
    cx_bn_t fq_M; cx_bn_alloc_init(&fq_M, 32, fq_m, 32);
    cx_bn_mont_ctx_t ctx;
    #ifndef DEBUG
    cx_mont_alloc(&ctx, 32);
    cx_mont_init(&ctx, fq_M);
    #endif

    bn_extended_point_t acc;
    bn_init_identity(&acc, &ctx);

    bn_extended_niels_point_t b;
    bn_load_extended_niels(&b, base, &ctx);

    int j0 = 4; // skip highest 4 bits (always set to 0 for Fr)
    for (int i = 0; i < 32; i++) {
        uint8_t c = (*x)[i];
        for (int j = j0; j < 8; j++) {
            bn_ext_double(&acc, fq_M, &ctx);
            if (((c >> (7-j)) & 1) != 0) {
                bn_ext_add(&acc, &b, fq_M, &ctx);
            }
        }
        j0 = 0;
    }
    bn_store_extended(v, &acc, &ctx);
    PRINTF("U: %.*H\n", 32, v->u);
    PRINTF("V: %.*H\n", 32, v->v);
    PRINTF("Z: %.*H\n", 32, v->z);
    PRINTF("T1: %.*H\n", 32, v->t1);
    PRINTF("T2: %.*H\n", 32, v->t2);

    cx_bn_unlock();
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

void simple_point_test() {
    extended_point_t p;
    ext_set_identity(&p);
    for (int i = 0; i < 3; i++) {
        ext_add(&p, &SPENDING_GENERATOR_NIELS);
        ext_double(&p);
    }
    PRINTF("U: %.*H\n", 32, p.u);
    PRINTF("V: %.*H\n", 32, p.v);
    PRINTF("Z: %.*H\n", 32, p.z);
    PRINTF("T1: %.*H\n", 32, p.t1);
    PRINTF("T2: %.*H\n", 32, p.t2);

    cx_bn_lock(32, 0);
    cx_bn_t fq_M; cx_bn_alloc_init(&fq_M, 32, fq_m, 32);
    cx_bn_mont_ctx_t ctx;
    #ifndef DEBUG
    cx_mont_init(&ctx, fq_M);
    #endif

    bn_extended_point_t p2;
    bn_init_identity(&p2, &ctx);

    bn_extended_niels_point_t b;
    bn_load_extended_niels(&b, &SPENDING_GENERATOR_NIELS, &ctx);
    for (int i = 0; i < 3; i++) {
        bn_ext_add(&p2, &b, fq_M, &ctx);
        bn_ext_double(&p2, fq_M, &ctx);
    }
    bn_store_extended(&p, &p2, &ctx);
    cx_bn_unlock();

    PRINTF("U: %.*H\n", 32, p.u);
    PRINTF("V: %.*H\n", 32, p.v);
    PRINTF("Z: %.*H\n", 32, p.z);
    PRINTF("T1: %.*H\n", 32, p.t1);
    PRINTF("T2: %.*H\n", 32, p.t2);

}
