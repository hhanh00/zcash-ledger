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
#include <lcx_sha256.h>
#include <lcx_ripemd160.h>
#include <lcx_hash.h>

#include "key.h"
#include "fr.h"
#include "globals.h"
#include "address.h"

int derive_pubkey(uint8_t *pk, uint8_t account) {
    uint8_t tsk[32];
    cx_ecfp_private_key_t t_prvk;
    cx_ecfp_public_key_t t_pubk;
    derive_tsk(tsk, account);
    cx_ecfp_init_private_key_no_throw(CX_CURVE_SECP256K1, tsk, 32, &t_prvk);
    cx_ecfp_generate_pair(CX_CURVE_SECP256K1, &t_pubk, &t_prvk, 1);
    PRINTF("PK: %.*H\n", 65, t_pubk.W);

    memmove(pk + 1, t_pubk.W + 1, 32); // X
    pk[0] = ((t_pubk.W[64] & 1) == 0) ? 0x02 : 0x03; // parity of Y
    PRINTF("CPK: %.*H\n", 33, pk);

    memmove(G_context.transparent_key_info.pub_key, pk, 33);

    return 0;
}

int derive_taddress(uint8_t *pkh, uint8_t account) {
    uint8_t pk[33];
    derive_pubkey(pk, account);
    
    cx_sha256_init_no_throw(&G_store.sha_hasher);
    cx_hash_no_throw((cx_hash_t *)&G_store.sha_hasher, CX_LAST, pk, 33, pk, 32);
    PRINTF("SHA256: %.*H\n", 32, pk);

    cx_ripemd160_init_no_throw(&G_store.ripemd_hasher);
    cx_hash_no_throw((cx_hash_t *)&G_store.ripemd_hasher, CX_LAST, pk, 32, pkh, 20);
    PRINTF("PKH: %.*H\n", 20, pkh);

    return 0;
}

int transparent_derive_pubkey(uint8_t account) {
    derive_pubkey(G_context.transparent_key_info.pub_key, account);
    derive_taddress(G_context.transparent_key_info.pkh, account);

    return 0;
}

void transparent_ecdsa(uint8_t *signature, uint8_t *key, const uint8_t *hash) {
    cx_get_random_bytes(G_store.rnd, 32);

    // compute the sig
    CX_THROW(cx_bn_lock(32, 0));

    cx_ecpoint_t Q;
    // --> compute Q = k.G
    cx_ecpoint_alloc(&Q, CX_CURVE_SECP256K1);
    cx_ecdomain_generator_bn(CX_CURVE_SECP256K1, &Q);

    CX_THROW(cx_ecpoint_rnd_scalarmul(&Q, G_store.rnd, 32));

    // load order
    BN_DEF(n);
    cx_ecdomain_parameter_bn(CX_CURVE_SECP256K1, CX_CURVE_PARAM_Order, n);

    // compute r
    BN_DEF(r);
    cx_ecpoint_export_bn(&Q, &r, NULL);
    cx_ecpoint_destroy(&Q);
    int diff;
    cx_bn_cmp(r, n, &diff);
    if (diff >= 0)
        cx_bn_sub(r, r, n);

    BN_DEF(s);
    BN_DEF(t);
    BN_DEF(v);
    BN_DEF(t1);
    BN_DEF(t2);
    BN_DEF(zero); cx_bn_set_u32(zero, 0);

    // compute s = kinv(h+d.x)
    //
    // t random, 0 <= t < n
    // v = d - t
    // u = h + (d-t)*x +t*x  = h + v*x + t*x
    // s = k_inv*u
    //

    cx_bn_rng(t, n);
    cx_bn_init(t1, key, 32);
    cx_bn_mod_sub(v, t1, t, n);                         // v
    cx_bn_mod_mul(t2, v, r, n);                         // v.x
    cx_bn_mod_mul(t1, t, r, n);                         // t.x

    cx_bn_init(v, hash, 32);                            // v = h
    cx_bn_mod_add(v, v, t1, n);                         // v += t.x
    cx_bn_mod_add(v, v, t2, n);                         // v += v.x
    cx_bn_mod_sub(v, v, zero, n);
    cx_bn_init(t1, G_store.rnd, 32);                            // k
    cx_bn_mod_invert_nprime(t2, t1, n);                 // k_inv
    cx_bn_mod_mul(s, v, t2, n);                         // s = k_inv*u

    // if s > order/2, s = -s = order-s
    cx_bn_sub(t1, n, s);
    cx_bn_shr(n, 1);
    cx_bn_cmp(s, n, &diff);
    if (diff > 0) {
        cx_bn_copy(s, t1);
    }

    cx_bn_export(r, signature, 32);
    cx_bn_export(s, signature + 32, 32);

    cx_bn_unlock();
}
