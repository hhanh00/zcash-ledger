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

#include <lcx_ecfp.h>
#include <lcx_hash.h>
#include <ox_bn.h>
#include "blake2s.h"

#include "sw.h"
#include "key.h"
#include "ff1.h"
#include "address.h"
#include "tx.h"
#include "transparent.h"
#include "globals.h"
#include "../ui/display.h"
#include "../ui/menu.h"
#include "../helper/send_response.h"

static cx_bn_t M; // M is the modulus in the base field of jubjub, Fq
static const uint8_t mont_h[] = {
    0x07, 0x48, 0xd9, 0xd9, 0x9f, 0x59, 0xff, 0x11, 0x05, 0xd3, 0x14, 0x96, 0x72, 0x54, 0x39, 0x8f, 0x2b, 0x6c, 0xed, 0xcb, 0x87, 0x92, 0x5c, 0x23, 0xc9, 0x99, 0xe9, 0x90, 0xf3, 0xf2, 0x9c, 0x6d
};

#include "fr.h"
#include "mont.h"
#include "sapling.h"

/// q is the modulus of Fq
/// q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
static const uint8_t fq_m[32] = {
  0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 
  0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05, 
  0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 
  0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01    
};

/// r is the modulus of Fr
/// r = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7
static const uint8_t fr_m[32] = {
  0x0e, 0x7d, 0xb4, 0xea, 0x65, 0x33, 0xaf, 0xa9, 
  0x06, 0x67, 0x3b, 0x01, 0x01, 0x34, 0x3b, 0x00, 
  0xa6, 0x68, 0x20, 0x93, 0xcc, 0xc8, 0x10, 0x82, 
  0xd0, 0x97, 0x0e, 0x5e, 0xd6, 0xf7, 0x2c, 0xb7
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

void init_ph(pedersen_state_t *state);
void destroy_ph(pedersen_state_t *state);
void update_ph(pedersen_state_t *state, uint8_t *data, size_t data_bit_len);
void finalize_ph(pedersen_state_t *state);

void swap_endian(uint8_t *data, int8_t len);
void en_mul(jj_e_t *pk, jj_en_t *G, cx_bn_t sk);
void e_double(jj_e_t *r);
void een_add_assign(jj_e_t *x, jj_en_t *y);
void e_to_bytes(uint8_t *pkb, jj_e_t *p);
void e_to_u(uint8_t *ub, const jj_e_t *p);

void sk_to_pk(uint8_t *pkb, jj_en_t *g, cx_bn_t sk);
int hash_to_e(jj_e_t *p, const uint8_t *msg, size_t len);

static void get_ivk(uint8_t *ivk, uint8_t *ak, uint8_t *nk);

static int derive_spending_key(uint8_t *spk, uint8_t account);

static void prf_expand_spending_key(uint8_t *buffer, uint8_t *key, uint8_t t);
static void reduce_wide_bytes(cx_bn_t dest, uint8_t *src, cx_bn_t M);

static void alloc_e(jj_e_t *r);
static void alloc_en(jj_en_t *r);
static void destroy_e(jj_e_t *r);
static void destroy_en(jj_en_t *r);

static void load_en(jj_en_t *dest, const ff_jj_en_t *src);
static void e_to_en(jj_en_t *dest, jj_e_t *src);
static void e_set0(jj_e_t *r);

#define min(a, b) ((a) > (b) ? (b) : (a))

#ifdef TEST
static void print_mont_inner(const char *label, cx_bn_t x) {
    BN_DEF(v); cx_bn_copy(v, x);
    FROM_MONT(v);
    print_bn(label, v);
    cx_bn_destroy(&v);
}
#define print_mont(label, x) print_mont_inner(label, x)
#else
#define print_mont(label, x)
#endif

#ifdef TEST
static void print_e_inner(jj_e_t *p) {
    print_mont("u", p->u);
    print_mont("v", p->v);
    print_mont("z", p->z);
    print_mont("t1", p->t1);
    print_mont("t2", p->t2);
}
#define print_e(p) print_e_inner(p)
#else
#define print_e(p)
#endif

static uint8_t buffer[64];

/**
 * spending_key -> ask, nsk, ovk, dk
 * ask -> ak
 * nsk -> nk
 * ak, nk -> ivk
 * dk -> d
 * d -> Gd
 * Gd, ivk -> pkd
 * d, pkd -> address
 * 
 * stack usage = hash (2) + spk + ask + nsk + ovk + dk + ak + nk + ivk + d (1/3) + pkd
*/
void sapling_derive_spending_key(uint8_t account) {
    ui_display_processing("z-key");
    expanded_spending_key_t *pkeys = &G_context.exp_sk_info;
    PRINTF("Derive sapling keys for account %d\n", account);

    uint8_t spk[32];

    derive_spending_key(spk, account);

    PRINTF("Spending key %.*H\n", 32, spk);
    cx_bn_lock(32, 0);
    BN_DEF(rM); cx_bn_init(rM, fr_m, 32);
    init_mont(fq_m);

    BN_DEF(temp);
    // derive the first layer of keys
    // ask, nsk are scalars obtained by hashing into 512 bit integer and then reducing mod R
    // ovk, dk are the first 256 bits of the 512 bit hash
    prf_expand_spending_key(buffer, spk, 0);
    PRINTF("ask %.*H\n", 64, buffer);
    reduce_wide_bytes(temp, buffer, rM);
    cx_bn_export(temp, pkeys->ask, 32);

    prf_expand_spending_key(buffer, spk, 1);
    reduce_wide_bytes(temp, buffer, rM);
    cx_bn_export(temp, pkeys->nsk, 32);
    cx_bn_destroy(&temp);

    prf_expand_spending_key(buffer, spk, 2);
    memmove(pkeys->ovk, buffer, 32);

    prf_expand_spending_key(buffer, spk, 0x10);
    memmove(pkeys->dk, buffer, 32);

    PRINTF("ask %.*H\n", 32, pkeys->ask);
    PRINTF("nsk %.*H\n", 32, pkeys->nsk);
    PRINTF("ovk %.*H\n", 32, pkeys->ovk);
    PRINTF("dk %.*H\n", 32, pkeys->dk);

    // ak is the byte representation of A = G.ask where G is the spending auth generator point
    BN_DEF(ask); cx_bn_init(ask, pkeys->ask, 32);
    jj_en_t G; alloc_en(&G); load_en(&G, &SPENDING_GEN);
    sk_to_pk(G_context.proofk_info.ak, &G, ask);
    PRINTF("ak %.*H\n", 32, G_context.proofk_info.ak);
    cx_bn_destroy(&ask);
    destroy_en(&G);

    // same thing with nsk -> nk
    BN_DEF(nsk); cx_bn_init(nsk, pkeys->nsk, 32);
    jj_en_t G2; alloc_en(&G2); load_en(&G2, &PROOF_GEN);
    sk_to_pk(G_context.proofk_info.nk, &G2, nsk);
    PRINTF("nk %.*H\n", 32, G_context.proofk_info.nk);
    cx_bn_destroy(&nsk);
    destroy_en(&G2);

    get_ivk(pkeys->pk_d, G_context.proofk_info.ak, G_context.proofk_info.nk); // use pk_d as ivk to save on space
    PRINTF("ivk %.*H\n", 32, pkeys->pk_d);

    // Find the first diversifier = default address
    uint32_t i = 0;
    PRINTF("dk %.*H\n", 32, pkeys->dk);
    jj_e_t Gd; alloc_e(&Gd);
    for (;i < 500;) {
        memset(pkeys->d, 0, 11);
        memmove(pkeys->d, &i, 4); // Try this index
        ff1_inplace(pkeys->dk, pkeys->d); // Shuffle with ff1
        PRINTF("di %.*H\n", 11, pkeys->d);

        int error = hash_to_e(&Gd, pkeys->d, 11);
        PRINTF("hash_to_e %d\n", error);
        if (!error) break;
        i++;
    }

    // Convert G to ext niels
    alloc_en(&G);
    e_to_en(&G, &Gd);
    destroy_e(&Gd);
    print_bn("vpu", G.vpu);
    print_bn("vmu", G.vmu);
    print_bn("z", G.z);
    print_bn("t2d", G.t2d);
    swap_endian(pkeys->pk_d, 32); // that's in fact ivk
    BN_DEF(ivk); cx_bn_init(ivk, pkeys->pk_d, 32);
    sk_to_pk(pkeys->pk_d, &G, ivk); // pkd = Gd.ivk
    destroy_en(&G);

    PRINTF("pkd %.*H\n", 32, pkeys->pk_d);
    // to_address_bech32(G_context.address, pkeys->d, pkeys->pk_d);
    // PRINTF("address %s\n", G_context.address);

    cx_bn_unlock();
    ui_menu_main();
}

/// @brief Sign a sig_hash using the secret key ask
/// randomized by alpha. 
/// alpha comes from our PRNG
/// @param signature 
/// @param sig_hash 
void sapling_sign(uint8_t *signature, uint8_t *sig_hash) {
    // PRINTF("sig hash %.*H\n", 32, sig_hash);
    cx_bn_lock(32, 0); 
    BN_DEF(rM); cx_bn_alloc_init(&rM, 32, fr_m, 32); // Use scalar field
    // use signature buffer as temporary storage
    // signature has 64 bytes, it will be used to store H* output
    // wide is a BN with 64 bytes used for the same purpose
    cx_bn_t wide; cx_bn_alloc(&wide, 64);

    cx_blake2b_t hasher; // Hasher for H*
    cx_hash_t *ph = (cx_hash_t *)&hasher;
    cx_blake2b_init2_no_throw(&hasher, 512,
                              NULL, 0, (uint8_t *) "Zcash_RedJubjubH", 16);
    cx_get_random_bytes(signature, 64);
    cx_hash(ph, 0, signature, 64, NULL, 0);
    cx_get_random_bytes(signature, 16);
    cx_hash(ph, 0, signature, 16, NULL, 0); // first 80 bytes are random

    // generate a random alpha in Fr
    prf_chacha(&chacha_alpha_rng, signature, 64); // pick a random alpha (64 bytes)
    // PRINTF("pre-ALPHA %.*H\n", 64, signature);
    BN_DEF(rsk); // it is going to be r but use it for alpha for now
    reduce_wide_bytes(rsk, signature, rM);
    // print_bn("ALPHA", rsk);

    // rerandomize the authorization key with alpha as ask
    // ask is going to be this signature secret key
    BN_DEF(ask); cx_bn_init(ask, G_context.exp_sk_info.ask, 32);
    // print_bn("ask", ask);
    cx_bn_mod_add_fixed(ask, ask, rsk, rM); // ask is now re-randomized by alpha
    // print_bn("SK", ask);

    init_mont(fq_m);
    // generate a unique keypair
    // nonce = H*(random|Abar|sig_hash)
    // where Abar = bytes(ask.G)
    jj_e_t ak; alloc_e(&ak);
    jj_en_t G; alloc_en(&G); load_en(&G, &SPENDING_GEN);
    en_mul(&ak, &G, ask);
    uint8_t abar[32];
    e_to_bytes(abar, &ak);
    // PRINTF("PK %.*H\n", 32, abar);
    // 80 bytes of randomness were added earlier
    cx_hash(ph, 0, abar, 32, NULL, 0); // Abar
    cx_hash(ph, CX_LAST, sig_hash, 32, signature, 64); // sig_hash
    // PRINTF("H* %.*H\n", 64, signature);

    // reduce to scalar field like we did for alpha
    reduce_wide_bytes(rsk, signature, rM);
    // print_bn("rsk", rsk);

    en_mul(&ak, &G, rsk); // ak = R = r.G
    uint8_t rbar[32];
    e_to_bytes(rbar, &ak);
    // PRINTF("Rbar %.*H\n", 32, rbar);
    // PRINTF("Abar %.*H\n", 32, abar);
    // PRINTF("sig_hash %.*H\n", 32, sig_hash);

    // H(rbar|abar|sig_hash)
    cx_blake2b_init2_no_throw(&hasher, 512,
                              NULL, 0, (uint8_t *) "Zcash_RedJubjubH", 16);
    cx_hash(ph, 0, rbar, 32, NULL, 0); // Rbar
    cx_hash(ph, 0, abar, 32, NULL, 0); // Abar
    cx_hash(ph, CX_LAST, sig_hash, 32, signature, 64); // sig_hash
    // signature = H(R|A|sig_hash)
    // reduce to scalar
    // PRINTF("H* %.*H\n", 64, signature);

    BN_DEF(ar); reduce_wide_bytes(ar, signature, rM);
    // print_bn("S", ar);
    // S = H(R|A|sig_hash) [rM]

    // r + S * sk
    BN_DEF(temp);
    cx_bn_mod_mul(temp, ar, ask, rM);
    // print_bn("S.sk", temp);
    cx_bn_mod_add_fixed(temp, temp, rsk, rM);
    // print_bn("r+S.sk", temp);
    
    memmove(signature, rbar, 32);
    cx_bn_export(temp, signature + 32, 32);
    swap_endian(signature + 32, 32);
    // PRINTF("r|s %.*H\n", 64, signature);

    cx_bn_unlock(); // no need to destroy BN individually
}

void sk_to_pk(uint8_t *pkb, jj_en_t *G, cx_bn_t sk) {
    jj_e_t pk; alloc_e(&pk);
    en_mul(&pk, G, sk);
    e_to_bytes(pkb, &pk);
    destroy_e(&pk);
}

/// @brief Reduce a 64 byte value modulo M
/// @param dest 32 bytes
/// @param src 64 bytes, src is modified!
/// @param mod
static void reduce_wide_bytes(cx_bn_t dest, uint8_t *src, cx_bn_t mod) {
    swap_endian(src, 64);
    cx_bn_t SRC; cx_bn_alloc_init(&SRC, 64, src, 64);
    cx_bn_reduce(dest, SRC, mod);
    cx_bn_destroy(&SRC);
}

/// @brief Derive the spending key. It is obtained by first using BIP-32 with path 
/// m/44'/133'/account'/0/0
/// Then hashing the result with Blake2b with perso ZSaplingSeedHash
/// @param spk 
/// @param account 
/// @return 
static int derive_spending_key(uint8_t *spk, uint8_t account) {
    derive_tsk(spk, account);

    cx_blake2b_init2_no_throw(&G_context.hasher, 256,
                              NULL, 0,
                              (uint8_t *) "ZSaplingSeedHash", 16);
    cx_hash((cx_hash_t *) &G_context.hasher,
            CX_LAST,
            spk, 32,
            spk, 32);
    return 0;
}

/// @brief blake2b(key|t) with perso = Zcash_ExpandSeed
/// @param pbuffer hash, 64 bytes
/// @param key
/// @param t domain
static void prf_expand_spending_key(uint8_t *pbuffer, uint8_t *key, uint8_t t) {
    cx_blake2b_init2_no_throw(&G_store.hasher, 512, NULL, 0, (uint8_t *)"Zcash_ExpandSeed", 16);
    cx_hash_t *ph = (cx_hash_t *)&G_store.hasher;
    cx_hash(ph, 0, key, 32, NULL, 0);
    cx_hash(ph, CX_LAST, &t, 1, pbuffer, 64);
}

static void alloc_e(jj_e_t *r) {
    cx_bn_alloc(&r->u, 32);
    cx_bn_alloc(&r->v, 32);
    cx_bn_alloc(&r->z, 32);
    cx_bn_alloc(&r->t1, 32);
    cx_bn_alloc(&r->t2, 32);
}

static void destroy_e(jj_e_t *r) {
    cx_bn_destroy(&r->u);
    cx_bn_destroy(&r->v);
    cx_bn_destroy(&r->z);
    cx_bn_destroy(&r->t1);
    cx_bn_destroy(&r->t2);
}

static void alloc_en(jj_en_t *r) {
    cx_bn_alloc(&r->vpu, 32);
    cx_bn_alloc(&r->vmu, 32);
    cx_bn_alloc(&r->z, 32);
    cx_bn_alloc(&r->t2d, 32);
}

static void destroy_en(jj_en_t *r) {
    cx_bn_destroy(&r->vpu);
    cx_bn_destroy(&r->vmu);
    cx_bn_destroy(&r->z);
    cx_bn_destroy(&r->t2d);
}

/// @brief load ff into bn, convert to MF
/// @param dest 
/// @param src 
static void load_en(jj_en_t *dest, const ff_jj_en_t *src) {
    cx_bn_init(dest->vpu, src->vpu, 32); TO_MONT(dest->vpu);
    cx_bn_init(dest->vmu, src->vmu, 32); TO_MONT(dest->vmu);
    cx_bn_init(dest->z, src->z, 32); TO_MONT(dest->z);
    cx_bn_init(dest->t2d, src->t2d, 32); TO_MONT(dest->t2d);
}

/// @brief Multiplies G by sk
/// @param pk output point in extended coord
/// @param G generator in extended niels coord
/// @param sk scalar
void en_mul(jj_e_t *pk, jj_en_t *G, cx_bn_t sk) {
    bool bit;
    e_set0(pk);
    // Skip the higest 4 bits as they are always 0 for Fr
    for (uint16_t i = 4; i < 256; i++) {
        cx_bn_tst_bit(sk, 255 - i, &bit);
        e_double(pk);
        PRINTF("*");
        if (bit) {
            PRINTF("+");
            een_add_assign(pk, G);
        }
    }
    PRINTF("\n");
    // print_mont("u", pk->u);
    // print_mont("v", pk->v);
    // print_mont("z", pk->z);
    // print_mont("t1", pk->t1);
    // print_mont("t2", pk->t2);
}

/// @brief set r to identity
/// @param r 
static void e_set0(jj_e_t *r) {
    // (0, 1, 1, 0, 0)
    cx_bn_set_u32(r->u, 0);
    cx_bn_set_u32(r->v, 1); TO_MONT(r->v);
    cx_bn_copy(r->z, r->v);
    cx_bn_copy(r->t1, r->u);
    cx_bn_copy(r->t2, r->u);
}

void e_double(jj_e_t *r) {
    BN_DEF(temp);
    BN_DEF(uu);
    cx_bn_copy(uu, r->u);
    CX_MUL(temp, uu, uu);
    cx_bn_copy(uu, temp);

    BN_DEF(vv);
    cx_bn_copy(vv, r->v);
    CX_MUL(temp, vv, vv);
    cx_bn_copy(vv, temp);

    BN_DEF(zz2);
    cx_bn_copy(zz2, r->z);
    CX_MUL(temp, zz2, zz2);
    cx_bn_copy(zz2, temp);
    cx_bn_mod_add_fixed(zz2, zz2, zz2, M);

    BN_DEF(uv2);
    cx_bn_mod_add_fixed(uv2, r->u, r->v, M);
    CX_MUL(temp, uv2, uv2);
    cx_bn_copy(uv2, temp);

    BN_DEF(vpu);
    cx_bn_mod_add_fixed(vpu, vv, uu, M); // vpu = v*v + u*u

    BN_DEF(vmu);
    cx_bn_mod_sub(vmu, vv, uu, M); // vmu = v*v - u*u

    BN_DEF(t);
    cx_bn_mod_sub(t, zz2, vmu, M);

    cx_bn_mod_sub(r->t1, uv2, vpu, M);
    cx_bn_copy(r->t2, vpu);
    CX_MUL(r->u, r->t1, t);
    CX_MUL(r->v, r->t2, vmu);
    CX_MUL(r->z, vmu, t);

    // print_mont("u", r->u);
    // print_mont("v", r->v);
    // print_mont("z", r->z);
    // print_mont("t1", r->t1);
    // print_mont("t2", r->t2);

    cx_bn_destroy(&temp);
    cx_bn_destroy(&t);
    cx_bn_destroy(&vmu);
    cx_bn_destroy(&vpu);
    cx_bn_destroy(&uv2);
    cx_bn_destroy(&zz2);
    cx_bn_destroy(&vv);
    cx_bn_destroy(&uu);
}

/// @brief x += y
/// @param r point in extended coord
/// @param a point in extended niels coord
void een_add_assign(jj_e_t *x, jj_en_t *y) {
    BN_DEF(temp);
    BN_DEF(a);
    BN_DEF(b);
    cx_bn_mod_sub(a, x->v, x->u, M); // a = (v - u) * vmu
    CX_MUL(temp, a, y->vmu);
    cx_bn_copy(a, temp);
    cx_bn_mod_add_fixed(b, x->v, x->u, M); // b = (v + u) * vpu
    CX_MUL(temp, b, y->vpu);
    cx_bn_copy(b, temp);

    BN_DEF(c);
    BN_DEF(d);
    CX_MUL(temp, x->t1, x->t2); 
    CX_MUL(c, temp, y->t2d); // c = t1 * t2 * t2d
    CX_MUL(d, x->z, y->z);
    cx_bn_mod_add_fixed(d, d, d, M); // d = 2zz

    BN_DEF(u);
    BN_DEF(v);
    cx_bn_mod_sub(u, b, a, M); // u = b - a
    cx_bn_mod_add_fixed(v, b, a, M); // v = b + a

    BN_DEF(z);
    BN_DEF(t);
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

/// @brief Convert from ext to ext niels
/// @param dest 
/// @param src 
void e_to_en(jj_en_t *dest, jj_e_t *src) {
    BN_DEF(D2); cx_bn_init(D2, fq_D2, 32); TO_MONT(D2);
    BN_DEF(temp);
    cx_bn_mod_add_fixed(dest->vpu, src->v, src->u, M);
    cx_bn_mod_sub(dest->vmu, src->v, src->u, M);
    cx_bn_copy(dest->z, src->z);
    CX_MUL(temp, src->t1, src->t2);
    CX_MUL(dest->t2d, temp, D2);
    cx_bn_destroy(&D2);
    cx_bn_destroy(&temp);
}

/// @brief convert a point into its compressed bytes representation
/// @param pkb v coord with highest bit set to the parity of u, in LE
/// @param p 
void e_to_bytes(uint8_t *pkb, jj_e_t *p) {
    BN_DEF(zinv);
    cx_bn_copy(zinv, p->z);
    cx_bn_mod_invert_nprime(zinv, zinv, M);

    // Do not use the Montgomery Multiplication because
    // zinv contains the 1/h factor equivalent to FROM_MONT
    BN_DEF(u);
    CX_BN_MOD_MUL(u, p->u, zinv);
    BN_DEF(v);
    CX_BN_MOD_MUL(v, p->v, zinv);

    bool sign; // put the parity of u into highest bit of v
    cx_bn_tst_bit(u, 0, &sign);
    if (sign)
        cx_bn_set_bit(v, 255);
    cx_bn_export(v, pkb, 32);
    swap_endian(pkb, 32); // to LE
    cx_bn_destroy(&zinv);
    cx_bn_destroy(&u);
    cx_bn_destroy(&v);
}

/// @brief Coordinate u extractor
/// @param u 32 bytes
/// @param p 
void e_to_u(uint8_t *ub, const jj_e_t *p) {
    BN_DEF(zinv);
    cx_bn_copy(zinv, p->z);
    cx_bn_mod_invert_nprime(zinv, zinv, M);

    // Do not use the Montgomery Multiplication because
    // zinv contains the 1/h factor equivalent to FROM_MONT
    BN_DEF(u);
    CX_BN_MOD_MUL(u, p->u, zinv);

    cx_bn_export(u, ub, 32);
    swap_endian(ub, 32);
    cx_bn_destroy(&zinv);
    cx_bn_destroy(&u);
}

/// @brief hash into an extended point
/// @param p 
/// @param msg 
/// @param len 
/// @return CX_INVALID_PARAMETER if hash does not correspond to a point
int hash_to_e(jj_e_t *p, const uint8_t *msg, size_t len) {
    int cx_error = 0;
    memset(&G_store.hash_params, 0, sizeof(G_store.hash_params));
    G_store.hash_params.digest_length = 32;
    G_store.hash_params.fanout = 1;
    G_store.hash_params.depth = 1;
    memmove(&G_store.hash_params.personal, "Zcash_gd", 8);

    blake2s_init_param(&G_store.hash_ctx, &G_store.hash_params);
    blake2s_update(&G_store.hash_ctx, "096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0", 64);
    blake2s_update(&G_store.hash_ctx, msg, len);
    blake2s_final(&G_store.hash_ctx, G_store.hash, 32);

    BN_DEF(one); cx_bn_set_u32(one, 1); TO_MONT(one);
    BN_DEF(v); 
    BN_DEF(temp);
    BN_DEF(v2);
    BN_DEF(v2m1);
    BN_DEF(D); cx_bn_init(D, fq_D, 32); TO_MONT(D);
    BN_DEF(u2);
    BN_DEF(u);

    uint8_t sign = G_store.hash[31] >> 7;
    G_store.hash[31] &= 0x7F;
    swap_endian(G_store.hash, 32);

    cx_bn_init(v, G_store.hash, 32);
    int diff;
    cx_bn_cmp(v, M, &diff);
    if (diff >= 0) {
        cx_error = CX_INVALID_PARAMETER;
        goto end;
    }

    TO_MONT(v);
    CX_MUL(v2, v, v);

    cx_bn_mod_sub(v2m1, v2, one, M); // v2-1

    CX_MUL(temp, v2, D); //v2*D
    cx_bn_mod_add_fixed(v2, temp, one, M); //v2*D+1 (*h)
    cx_bn_mod_invert_nprime(temp, v2, M); // 1/(v2*D+1) (/h)

    // Don't use Mont. Mult because temp has 1/h
    CX_BN_MOD_MUL(u2, v2m1, temp); // u2 = (v2-1)/(v2*D+1)
    print_bn("u2", u2);

    cx_error = cx_bn_mod_sqrt(u, u2, M, sign);
    if (cx_error) {
        cx_error = CX_INVALID_PARAMETER;
        goto end;
    }
    TO_MONT(u);

    cx_bn_copy(p->u, u);
    cx_bn_copy(p->v, v);
    cx_bn_copy(p->z, one);
    cx_bn_copy(p->t1, u);
    cx_bn_copy(p->t1, v);
    
    e_double(p);
    e_double(p);
    e_double(p); // *8 (cofactor)

end:
    cx_bn_destroy(&v);
    cx_bn_destroy(&one);
    cx_bn_destroy(&temp);
    cx_bn_destroy(&v2);
    cx_bn_destroy(&v2m1);
    cx_bn_destroy(&D);
    cx_bn_destroy(&u2);
    cx_bn_destroy(&u);

    // PRINTF("vpu %.*H\n", 32, r->vpu);
    // PRINTF("vmu %.*H\n", 32, r->vmu);
    // PRINTF("z %.*H\n", 32, r->z);
    // PRINTF("t2d %.*H\n", 32, r->t2d);

    return cx_error;
}

void get_ivk(uint8_t *ivk, uint8_t *ak, uint8_t *nk) {
    memset(&G_store.hash_params, 0, sizeof(G_store.hash_params));
    G_store.hash_params.digest_length = 32;
    G_store.hash_params.fanout = 1;
    G_store.hash_params.depth = 1;
    memmove(&G_store.hash_params.personal, "Zcashivk", 8);

    blake2s_init_param(&G_store.hash_ctx, &G_store.hash_params);
    blake2s_update(&G_store.hash_ctx, ak, 32);
    blake2s_update(&G_store.hash_ctx, nk, 32);
    blake2s_final(&G_store.hash_ctx, ivk, 32);

    ivk[31] &= 0x07;
}

#ifdef TEST
uint8_t debug[250];
static uint8_t *pdebug;

static void write_debug(uint8_t label, uint8_t *data, size_t len) {
    *pdebug++ = label;
    memmove(pdebug, data, len); pdebug += len;
}
static void write_debug_bn(uint8_t label, cx_bn_t x) {
    uint8_t v[32];
    cx_bn_export(x, v, 32);
    write_debug(label, v, 5);
}
static cx_sha256_t sha_hasher;
static void write_debug_bn_hash(cx_bn_t x) {
    uint8_t v[32];
    cx_bn_export(x, v, 32);
    cx_sha256_init_no_throw(&sha_hasher);
    cx_hash_no_throw((cx_hash_t *)&sha_hasher, CX_LAST, v, 32, v, 32);
    *pdebug++ = v[0];
    // memmove(pdebug, v, 1); pdebug += 1;
}
static void write_debug_bn_tail(cx_bn_t x) {
    uint8_t v[32];
    cx_bn_export(x, v, 32);
    PRINTF("%.*H\n", 32, v);
    memmove(pdebug, v+28, 4); pdebug += 4;
}
static void write_debug_mont(uint8_t label, cx_bn_t x) {
    BN_DEF(t); cx_bn_copy(t, x); FROM_MONT(t);
    uint8_t v[32];
    cx_bn_export(t, v, 32);
    write_debug(label, v, 5);
    cx_bn_destroy(&t);
}
#endif

/// @brief computes the note commitment
/// @param cmu 
/// @param d 
/// @param pkd 
/// @param value 
/// @param rseed 
/// throws if address is not valid
void get_cmu(uint8_t *cmu, uint8_t *d, uint8_t *pkd, uint64_t value, uint8_t *rseed) {    
    cx_bn_lock(32, 0);
    init_mont(fq_m);
    BN_DEF(rM); cx_bn_init(rM, fr_m, 32);
    uint8_t rcmb[32];
    BN_DEF(rcm); prf_expand_spending_key(buffer, rseed, 4);
    reduce_wide_bytes(rcm, buffer, rM);
    cx_bn_export(rcm, rcmb, 32);
    PRINTF("rcm %.*H\n", 32, rcmb);

    PRINTF("init ph\n");
    init_ph(&G_store.ph);
    uint8_t perso = 0x3F;
    update_ph(&G_store.ph, &perso, 6);
    update_ph(&G_store.ph, (uint8_t *)&value, 64); // value
    PRINTF("value %.*H\n", 8, (uint8_t *)&value);
    jj_e_t Gd; alloc_e(&Gd);
    CX_THROW(hash_to_e(&Gd, d, 11)); // check if d is a good diversifier
    e_to_bytes(G_store.Gdb, &Gd);
    destroy_e(&Gd);
    PRINTF("Gd %.*H\n", 32, G_store.Gdb);
    update_ph(&G_store.ph, G_store.Gdb, 256); // Gd
    PRINTF("pkd %.*H\n", 32, pkd);
    update_ph(&G_store.ph, pkd, 256); // pkd
    finalize_ph(&G_store.ph);

    jj_en_t Gcmu; alloc_en(&Gcmu); load_en(&Gcmu, &CMU_RAND_GEN);
    jj_e_t pkcmu; alloc_e(&pkcmu);
    en_mul(&pkcmu, &Gcmu, rcm);
    e_to_en(&Gcmu, &pkcmu);
    een_add_assign(&G_store.ph.hash, &Gcmu);
    destroy_en(&Gcmu);
    destroy_e(&pkcmu);

    print_e(&G_store.ph.hash);

    e_to_u(cmu, &G_store.ph.hash);

    destroy_ph(&G_store.ph);
    cx_bn_destroy(&rcm);
    cx_bn_destroy(&rM);
    cx_bn_unlock();
}

static void process_chunk(pedersen_state_t *state);
static void process_acc(pedersen_state_t *state);

void init_ph(pedersen_state_t *state) {
    memset(state, 0, sizeof(pedersen_state_t));
    alloc_e(&state->hash); e_set0(&state->hash);
    cx_bn_alloc(&state->zero, 32); cx_bn_set_u32(state->zero, 0);
    cx_bn_alloc(&state->cur, 32); cx_bn_set_u32(state->cur, 1);
    cx_bn_alloc(&state->acc, 32); cx_bn_set_u32(state->acc, 0);
    cx_bn_alloc(&state->M, 32); cx_bn_init(state->M, fr_m, 32);
}

void destroy_ph(pedersen_state_t *state) {
    destroy_e(&state->hash);
    cx_bn_destroy(&state->zero);
    cx_bn_destroy(&state->cur);
    cx_bn_destroy(&state->acc);
    cx_bn_destroy(&state->M);
}

void update_ph(pedersen_state_t *state, uint8_t *data, size_t data_bit_len) {
    size_t byte_length = (data_bit_len + 7) / 8;

    for (size_t i = 0; i < byte_length; i++) {
        uint8_t byte = data[i];
        // process 8 bits at a time, until the last byte if it is not an full byte
        int bits_to_process = (i == byte_length - 1 && data_bit_len % 8 != 0) ? data_bit_len % 8 : 8;

        // emit in chunks of 3 bits
        while (bits_to_process > 0) {
            // number of bits needed to fill up our current pack
            int bits_to_add = min(3 - state->bits_in_pack, bits_to_process);

            // mask that extracts 'bits_to_add' bits
            uint8_t mask = ((1 << bits_to_add) - 1);
            // take these bits in LE from the byte input
            uint8_t bits = byte & mask; 
            // add them in front of the current pack
            state->current_pack |= (bits << state->bits_in_pack);

            // shift the input byte to remove the extracted bits
            byte >>= bits_to_add;

            // update our counts
            state->bits_in_pack += bits_to_add;
            bits_to_process -= bits_to_add;

            // if the pack is full, emit it
            if (state->bits_in_pack == 3) {
                process_chunk(state);
                state->bits_in_pack = 0;
                state->current_pack = 0;
            }
        }
    }
}

void finalize_ph(pedersen_state_t *state) {
    // process the last partial chunk if any
    if (state->bits_in_pack > 0) {
        process_chunk(state);
        state->bits_in_pack = 0;
    }
    process_acc(state);
    print_e(&state->hash);
}

static void process_chunk(pedersen_state_t *state) {
    uint8_t c = state->current_pack;
    // accumulate 3 bits into state->acc
    // scale state->cur
    BN_DEF(temp); cx_bn_copy(temp, state->cur); // temp = cur
    if ((c & 1) != 0) {
        // PRINTF("+");
        cx_bn_mod_add_fixed(temp, temp, state->cur, state->M); // temp += cur
    }
    cx_bn_mod_add_fixed(state->cur, state->cur, state->cur, state->M); // double cur
    if ((c & 2) != 0) {
        // PRINTF("+");
        cx_bn_mod_add_fixed(temp, temp, state->cur, state->M); // temp += cur
    }
    if ((c & 4) != 0) {
        // PRINTF("-");
        cx_bn_mod_sub(temp, state->zero, temp, state->M); // temp = -temp
    }
    cx_bn_mod_add_fixed(state->cur, state->cur, state->cur, state->M); // double cur
    cx_bn_mod_add_fixed(state->cur, state->cur, state->cur, state->M); // double cur
    cx_bn_mod_add_fixed(state->cur, state->cur, state->cur, state->M); // double cur
    // PRINTF("=\n");
    // print_bn("temp", temp);
    cx_bn_mod_add_fixed(state->acc, state->acc, temp, state->M); // acc += temp
    cx_bn_destroy(&temp);

    if (state->index_pack % 63 == 62) {
        process_acc(state);
        cx_bn_set_u32(state->acc, 0);
        cx_bn_set_u32(state->cur, 1);
    }

    state->index_pack++;
}

/// @brief process a group of 63 chunks, use one of the PH generators
/// we need 4 points for the data that we hash
/// @param state 
static void process_acc(pedersen_state_t *state) {
    print_bn("acc", state->acc);
    uint8_t index_gen = state->index_pack / 63;
    jj_en_t G; alloc_en(&G); load_en(&G, &PH_GENS[index_gen]);
    jj_e_t pk; alloc_e(&pk);
    en_mul(&pk, &G, state->acc);
    e_to_en(&G, &pk);
    een_add_assign(&state->hash, &G);
    destroy_e(&pk);
    destroy_en(&G);
}

#ifdef TEST
int test_cmu(uint8_t *data) {
    pdebug = debug;
    cx_bn_lock(32, 0);
    init_mont(fq_m);
    PRINTF("init ph\n");
    init_ph(&G_store.ph);
    uint8_t perso = 0x3F;
    update_ph(&G_store.ph, &perso, 6);
    update_ph(&G_store.ph, data, (8+32+32)*8);
    finalize_ph(&G_store.ph);
    uint8_t cmu[32];
    e_to_u(cmu, &G_store.ph.hash);
    PRINTF("cmu %.*H\n", 32, cmu);
    cx_bn_unlock();
    return helper_send_response_bytes(debug, 250);
}
#endif
