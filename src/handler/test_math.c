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
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // memset, explicit_bzero

#include "os.h"
#include "cx.h"

#include "../globals.h"
#include "../types.h"
#include "../io.h"
#include "../sw.h"
#include "../common/buffer.h"
#include "../ui/display.h"
#include "../helper/send_response.h"
#include "../crypto/fr.h"
#include "../crypto/prf.h"
#include "../crypto/pallas.h"

fv_t ask; // authorization key
fp_t nk; // nullifier key
fv_t rivk; // randomized ivk
uint8_t ak[32]; // authorization public key
uint8_t dk[32]; // diversifier key

int handler_test_math() {
    int error = 0;
    fq_t d2;
    BEGIN_TRY {
        TRY {
            uint8_t hash[64];
            memset(hash, 1, 32);

            // SpendingKey => SpendAuthorizingKey
            prf_expand_seed(hash, 0x06); // hash to 512 bit value
            PRINTF("PRF EXPAND 6 %.*H\n", 64, hash);
            fv_from_wide(hash); // reduce to pallas scalar
            PRINTF("TO SCALAR %.*H\n", 32, hash);
            memmove(ask, hash, 32);
            PRINTF("SPENDING AUTHORIZATION KEY %.*H\n", 32, ask);

            jac_p_t p;
            pallas_base_mult(&p, &SPEND_AUTH_GEN, &ask);
            pallas_to_bytes(ak, &p);

            memset(hash, 1, 32);
            prf_expand_seed(hash, 0x07); // hash to 512 bit value
            PRINTF("PRF EXPAND 7 %.*H\n", 64, hash);
            fp_from_wide(hash); // reduce to pallas base
            PRINTF("TO BASE %.*H\n", 32, hash);
            memmove(nk, hash, 32);
            PRINTF("NULLIFIER DERIVATION KEY %.*H\n", 32, nk);

            memset(hash, 1, 32);
            prf_expand_seed(hash, 0x08); // hash to 512 bit value
            PRINTF("PRF EXPAND 8 %.*H\n", 64, hash);
            fv_from_wide(hash); // reduce to pallas scalar
            PRINTF("TO SCALAR %.*H\n", 32, hash);
            memmove(rivk, hash, 32);
            PRINTF("RIVK %.*H\n", 32, rivk);

            memmove(hash, rivk, 32); 
            swap_endian(hash, 32); // to_repr
            uint8_t dst = 0x82;
            cx_blake2b_t hash_ctx;
            cx_blake2b_init2_no_throw(&hash_ctx, 512, NULL, 0, (uint8_t *)"Zcash_ExpandSeed", 16);
            PRINTF("rivk %.*H\n", 32, hash);
            cx_hash((cx_hash_t *)&hash_ctx, 0, hash, 32, NULL, 0);
            PRINTF("dst %.*H\n", 1, &dst);
            cx_hash((cx_hash_t *)&hash_ctx, 0, &dst, 1, NULL, 0);
            PRINTF("ak %.*H\n", 32, ak);
            cx_hash((cx_hash_t *)&hash_ctx, 0, ak, 32, NULL, 0);
            memmove(hash, nk, 32); 
            swap_endian(hash, 32); // to_repr
            PRINTF("nk %.*H\n", 32, hash);
            cx_hash((cx_hash_t *)&hash_ctx, 0, hash, 32, NULL, 0);
            cx_hash((cx_hash_t *)&hash_ctx, CX_LAST, NULL, 0, hash, 64);
            PRINTF("ivk %.*H\n", 64, hash);

            memmove(dk, hash, 32);

            // PRINTF("p.x %.*H\n", 32, &p.x);
            // PRINTF("p.y %.*H\n", 32, &p.y);
            // PRINTF("p.z %.*H\n", 32, &p.z);

            // PRINTF("p %.*H\n", 32, hash);



            // cx_bn_lock(32, 0);
            // cx_bn_t M; cx_bn_alloc_init(&M, 32, fp_m, 32);
            // jac_p_bn_t gen;
            // pallas_jac_init(&gen, &SPEND_AUTH_GEN);
            // pallas_double_jac(&gen, M);
            // pallas_jac_export(&p, &gen);
            // cx_bn_unlock();

            // jac_p_t p;
            // hash_to_curve(&p, "z.cash:SinsemillaQ", 18, "z.cash:Orchard-MerkleCRH", 24);
            // PRINTF("p.x %.*H\n", 32, p.x);
            // PRINTF("p.y %.*H\n", 32, p.y);
            // PRINTF("p.z %.*H\n", 32, p.z);
        }
        CATCH_OTHER(e) {
            error = e;
        }
        FINALLY {
        }
    }
    END_TRY;
    if (error != 0) return io_send_sw(error);
    return helper_send_response_bytes(d2, 32);
}

// 628CF615D21CF30D41826ED13D4D4A1D3C9B8640E76AE52103E94683DDB8FB24
// a85a53bfdb32c3e519768fbc054e0f5ff7ad48a0e58a276078b38b2464f8dd15

// 24fbb8dd8346e90321e56ae740869b3c1d4a4d3dd16e82410df31cd215f68c62cc14620a8efd68b6991e6ff8f95caa2a47a65e21ccc02a89a93e951e2a6a777e
// 24FBB8DD8346E90321E56AE740869B3C1D4A4D3DD16E82410DF31CD215F68C62CC14620A8EFD68B6991E6FF8F95CAA2A47A65E21CCC02A89A93E951E2A6A777E

// a693b6030117ea11459e9095918dc762274efb2511ca5fa400471c7cb8706a5a32969525df9c14c452acacb35907e78f96fd35edb793d942cff62c6ad70cc066
// 0x1976e3e92c88e6df8a700c855be3715e23e947f761754f2a09a02e9a6ba996f1

// A693B6030117EA11459E9095918DC762274EFB2511CA5FA400471C7CB8706A5A32969525DF9C14C452ACACB35907E78F96FD35EDB793D942CFF62C6AD70CC066
// 5A6A70B87C1C4700A45FCA1125FB4E2762C78D9195909E4511EA170103B693A6

