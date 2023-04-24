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
#include "../crypto/sinsemilla.h"
#include "../crypto/ff1.h"
#include "../crypto/f4jumble.h"
#include "../crypto/ua.h"
#include "../crypto/tx.h"
#include "../crypto/orchard.h"

int handler_test_math(o_action_t *action) {
    int error = 0;
    fq_t d2;
    BEGIN_TRY {
        TRY {
            orchard_derive_spending_key(0);

            PRINTF("d %.*H\n", 11, action->address);
            PRINTF("pk_d %.*H\n", 32, action->address + 11);
            PRINTF("rho %.*H\n", 32, action->nf);
            PRINTF("amount %.*H\n", 8, &action->amount);

            uint8_t rseed[32];
            memset(rseed, 4, 32);
            cx_chacha_init(&chacha_rseed_rng, 20);
            cx_chacha_set_key(&chacha_rseed_rng, rseed, 32);
            prf_chacha(&chacha_rseed_rng, rseed, 32);
            PRINTF("rseed %.*H\n", 32, rseed);

            cmx(action->address, action->amount, rseed, action->nf);
            
            // return encode_ua();

            // uint8_t a[128];
            // memset(a, 1, 128);
            // f4jumble(a, 128);
            // PRINTF("a %.*H\n", 128, a);

            // return helper_send_response_bytes(NULL, 0);            
            // jac_p_t S;
            // sinsemilla_S(&S, 1);
            // PRINTF("S.x %.*H\n", 32, S.x);
            // PRINTF("S.y %.*H\n", 32, S.y);
            // PRINTF("S.z %.*H\n", 32, S.z);
            // pallas_to_bytes(hash, &S);
            // PRINTF("S.u %.*H\n", 32, hash);

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

