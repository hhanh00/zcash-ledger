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

static cx_bn_t M;
static const uint8_t mont_h[] = {
    0x07, 0x48, 0xd9, 0xd9, 0x9f, 0x59, 0xff, 0x11, 0x05, 0xd3, 0x14, 0x96, 0x72, 0x54, 0x39, 0x8f, 0x2b, 0x6c, 0xed, 0xcb, 0x87, 0x92, 0x5c, 0x23, 0xc9, 0x99, 0xe9, 0x90, 0xf3, 0xf2, 0x9c, 0x6d
};

#include "mont.h"

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

/**
 * This is very performance critical code. The SK -> PK
 * computation does a MSM. It will make thousands of 
 * modular additions and multiplications.
 * Therefore we want to tightly optimize this part.
 * 
 * - Use bn_ API instead of the math_ API. We don't lock/unlock
 * the BigNum unit for every op
 * - Use Montgomery multiplication
*/

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

void bn_init_identity(bn_extended_point_t *v) {
    cx_bn_alloc(&v->u, 32); cx_bn_set_u32(v->u, 0);
    cx_bn_alloc(&v->v, 32); cx_bn_set_u32(v->v, 1);
    cx_bn_alloc(&v->z, 32); cx_bn_set_u32(v->z, 1);
    cx_bn_alloc(&v->t1, 32); cx_bn_set_u32(v->t1, 0);
    cx_bn_alloc(&v->t2, 32); cx_bn_set_u32(v->t2, 0);
    TO_MONT(v->v);
    TO_MONT(v->z);
}

void bn_load_extended_niels(bn_extended_niels_point_t *v, const extended_niels_point_t *a) {
    cx_bn_alloc_init(&v->vpu, 32, a->vpu, 32);
    cx_bn_alloc_init(&v->vmu, 32, a->vmu, 32);
    cx_bn_alloc_init(&v->z, 32, a->z, 32);
    cx_bn_alloc_init(&v->t2d, 32, a->t2d, 32);
    TO_MONT(v->vpu);
    TO_MONT(v->vmu);
    TO_MONT(v->z);
    TO_MONT(v->t2d);
}

void bn_load_extended(bn_extended_point_t *v, const extended_point_t *a) {
    cx_bn_alloc_init(&v->u, 32, a->u, 32);
    cx_bn_alloc_init(&v->v, 32, a->v, 32);
    cx_bn_alloc_init(&v->z, 32, a->z, 32);
    cx_bn_alloc_init(&v->t1, 32, a->t1, 32);
    cx_bn_alloc_init(&v->t2, 32, a->t2, 32);
    TO_MONT(v->u);
    TO_MONT(v->v);
    TO_MONT(v->z);
    TO_MONT(v->t1);
    TO_MONT(v->t2);
}

void bn_store_extended(extended_point_t *v, const bn_extended_point_t *a) {
    FROM_MONT(a->u);
    FROM_MONT(a->v);
    FROM_MONT(a->z);
    FROM_MONT(a->t1);
    FROM_MONT(a->t2);
    cx_bn_export(a->u, v->u, 32);
    cx_bn_export(a->v, v->v, 32);
    cx_bn_export(a->z, v->z, 32);
    cx_bn_export(a->t1, v->t1, 32);
    cx_bn_export(a->t2, v->t2, 32);
}

static void bn_ext_double(bn_extended_point_t *v) {
    BN_DEF_ZERO;    
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
    cx_bn_mod_add_fixed(zz2, zz2, zz2, M);

    cx_bn_t uv2;
    cx_bn_alloc(&uv2, 32);
    
    cx_bn_mod_add_fixed(uv2, v->u, v->v, M);
    CX_MUL(temp, uv2, uv2);
    cx_bn_copy(uv2, temp);

    cx_bn_t vpu;
    cx_bn_alloc(&vpu, 32);
    cx_bn_mod_add_fixed(vpu, vv, uu, M); // vpu = v*v + u*u

    cx_bn_t vmu;
    cx_bn_alloc(&vmu, 32);
    cx_bn_mod_sub(vmu, vv, uu, M); // vmu = v*v - u*u

    cx_bn_t t;
    cx_bn_alloc(&t, 32);
    cx_bn_mod_sub(t, zz2, vmu, M);

    cx_bn_mod_sub(v->t1, uv2, vpu, M);
    cx_bn_copy(v->t2, vpu);
    CX_MUL(v->u, v->t1, t);
    CX_MUL(v->v, v->t2, vmu);
    CX_MUL(v->z, vmu, t);

    cx_bn_destroy(&zero);
    cx_bn_destroy(&temp);
    cx_bn_destroy(&t);
    cx_bn_destroy(&vmu);
    cx_bn_destroy(&vpu);
    cx_bn_destroy(&uv2);
    cx_bn_destroy(&zz2);
    cx_bn_destroy(&vv);
    cx_bn_destroy(&uu);
}

static void bn_ext_add(bn_extended_point_t *x, const bn_extended_niels_point_t *y) {
    BN_DEF_ZERO;  
    cx_bn_t temp; cx_bn_alloc(&temp, 32);
    cx_bn_t a; cx_bn_alloc(&a, 32);
    cx_bn_t b; cx_bn_alloc(&b, 32);
    cx_bn_mod_sub(a, x->v, x->u, M); // a = (v - u) * vmu
    CX_MUL(temp, a, y->vmu);
    cx_bn_copy(a, temp);
    cx_bn_mod_add_fixed(b, x->v, x->u, M); // b = (v + u) * vpu
    CX_MUL(temp, b, y->vpu);
    cx_bn_copy(b, temp);

    cx_bn_t c; cx_bn_alloc(&c, 32);
    cx_bn_t d; cx_bn_alloc(&d, 32);
    CX_MUL(temp, x->t1, x->t2); 
    CX_MUL(c, temp, y->t2d); // c = t1 * t2 * t2d
    CX_MUL(d, x->z, y->z);
    cx_bn_mod_add_fixed(d, d, d, M); // d = 2zz

    cx_bn_t u; cx_bn_alloc(&u, 32);
    cx_bn_t v; cx_bn_alloc(&v, 32);
    cx_bn_mod_sub(u, b, a, M); // u = b - a
    cx_bn_mod_add_fixed(v, b, a, M); // v = b + a

    cx_bn_t z; cx_bn_alloc(&z, 32);
    cx_bn_t t; cx_bn_alloc(&t, 32);
    cx_bn_mod_add_fixed(z, d, c, M); // z = d + c
    cx_bn_mod_sub(t, d, c, M); // t = d - c

    // print_bn("A", a);
    // print_bn("B", b);
    // print_bn("C", c);
    // print_bn("D", d);
    // print_bn("U", u);
    // print_bn("V", v);
    // print_bn("Z", z);
    // print_bn("T", t);

    cx_bn_destroy(&zero);
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
    init_mont((uint8_t *)fq_m);

    bn_extended_point_t acc;
    bn_init_identity(&acc);

    bn_extended_niels_point_t b;
    bn_load_extended_niels(&b, base);

    int j0 = 4; // skip highest 4 bits (always set to 0 for Fr)
    for (int i = 0; i < 32; i++) {
        uint8_t c = (*x)[i];
        for (int j = j0; j < 8; j++) {
            bn_ext_double(&acc);
            if (((c >> (7-j)) & 1) != 0) {
                bn_ext_add(&acc, &b);
            }
        }
        j0 = 0;
    }
    bn_store_extended(v, &acc);
    // PRINTF("U: %.*H\n", 32, v->u);
    // PRINTF("V: %.*H\n", 32, v->v);
    // PRINTF("Z: %.*H\n", 32, v->z);
    // PRINTF("T1: %.*H\n", 32, v->t1);
    // PRINTF("T2: %.*H\n", 32, v->t2);

    cx_bn_unlock();
}

void ext_add(extended_point_t *v, const extended_niels_point_t *a) {
    cx_bn_lock(32, 0);
    init_mont((uint8_t *)fq_m);
    bn_extended_point_t vv;
    bn_extended_niels_point_t aa;
    bn_load_extended(&vv, v);
    bn_load_extended_niels(&aa, a);
    bn_ext_add(&vv, &aa);
    bn_store_extended(v, &vv);
    cx_bn_unlock();
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
    // PRINTF("v %.*H\n", 32, v);

    uint8_t *pv = (uint8_t *)&v;

    uint8_t sign = pv[31] >> 7;
    pv[31] &= 0x7F;
    swap_endian(pv, 32);

    if (!fq_ok(&v)) {
        cx_bn_unlock();
        return CX_INVALID_PARAMETER;
    }

    cx_bn_lock(32, 0);
    init_mont((uint8_t *)fq_m);
    BN_DEF(one); cx_bn_set_u32(one, 1);
    BN_DEF(temp);
    BN_DEF(bn_v); cx_bn_init(bn_v, v, 32);
    BN_DEF(v2);
    CX_BN_MOD_MUL(v2, bn_v, bn_v);

    BN_DEF(v2m1);
    cx_bn_mod_sub(v2m1, v2, one, M); // v2-1

    BN_DEF(D); cx_bn_init(D, fq_D, 32);
    CX_BN_MOD_MUL(temp, v2, D); //v2*D
    cx_bn_mod_add_fixed(v2, temp, one, M); //v2*D+1
    cx_bn_mod_invert_nprime(temp, v2, M); // 1/(v2*D+1)
    BN_DEF(u2);
    CX_BN_MOD_MUL(u2, v2m1, temp); // u2 = (v2-1)/(v2*D+1)

    BN_DEF(bn_u);
    error = cx_bn_mod_sqrt(bn_u, u2, M, sign);

    fq_t u;
    cx_bn_export(bn_u, (uint8_t *)&u, 32);

    if (error) {
        cx_bn_unlock();
        return error;
    }

    bn_extended_point_t p;
    cx_bn_alloc(&p.u, 32); cx_bn_copy(p.u, bn_u); TO_MONT(p.u);
    cx_bn_alloc(&p.v, 32); cx_bn_copy(p.v, bn_v); TO_MONT(p.v);
    cx_bn_alloc(&p.z, 32); cx_bn_set_u32(p.z, 1); TO_MONT(p.z);
    cx_bn_alloc(&p.t1, 32); cx_bn_copy(p.t1, p.u);
    cx_bn_alloc(&p.t2, 32); cx_bn_copy(p.t1, p.v);
    
    bn_ext_double(&p);
    bn_ext_double(&p);
    bn_ext_double(&p); // *8 (cofactor)

    BN_DEF(temp2);
    BN_DEF(temp3);
    cx_bn_mod_add_fixed(temp, p.v, p.u, M); 
    FROM_MONT(temp); cx_bn_export(temp, r->vpu, 32);
    cx_bn_mod_sub(temp, p.v, p.u, M); 
    FROM_MONT(temp); cx_bn_export(temp, r->vmu, 32);
    FROM_MONT(p.z); cx_bn_export(p.z, r->z, 32);
    CX_MUL(temp, p.t1, p.t2);
    cx_bn_init(temp2, fq_D2, 32); // D2 is not in MF
    CX_MUL(temp3, temp, temp2); // no FROM_MONT needed because TO_MONT/FROM_MONT cancel out
    cx_bn_export(temp3, r->t2d, 32);

    cx_bn_unlock();

    // PRINTF("vpu %.*H\n", 32, r->vpu);
    // PRINTF("vmu %.*H\n", 32, r->vmu);
    // PRINTF("z %.*H\n", 32, r->z);
    // PRINTF("t2d %.*H\n", 32, r->t2d);

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

    cx_get_random_bytes(buffer, 80);
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
