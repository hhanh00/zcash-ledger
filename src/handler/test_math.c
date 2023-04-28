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
#include "../crypto/debug.h"

#define BN_DEF(a) cx_bn_t a; cx_bn_alloc(&a, 32);

const uint8_t ask[] = { 
    0x1A, 0x83, 0x3D, 0x7C, 0x27, 0x9D, 0xCD, 0xF5, 0x86, 0xC0, 0xFB, 0xAA, 0xCE, 0xB5, 0x36, 0x11, 0x9A, 0x12, 0x19, 0xA7, 0x3C, 0xEC, 0xD2, 0x14, 0x32, 0xA5, 0xD6, 0x25, 0x40, 0xE8, 0x7E, 0x7C
};

void test_hash_to_curve(uint8_t *r) {
    hash_to_curve(&r, (uint8_t *)"HELLO", 5, "Sent from YWallet", 17);
}

int handler_test_math(uint8_t i) {
    int error = 0;
    jac_p_t r;
    init_debug();
    BEGIN_TRY {
        TRY {


            // orchard_derive_spending_key(0);

            // CX_THROW(cx_bn_lock(32, 0)); 
            // BN_DEF(zero); cx_bn_set_u32(zero, 0);
            // BN_DEF(M); cx_bn_init(M, fp_m, 32);
            // BN_DEF(b); cx_bn_init(b, TEST_B, 32);
            // BN_DEF(c); cx_bn_init(c, TEST_B, 32);
            // BN_DEF(a);
            // CX_THROW(cx_bn_mod_add(a, b, c, M));
            // CX_THROW(cx_bn_mod_sub(a, a, zero, M));
            // CX_THROW(cx_bn_export(a, res, 32));

            // CX_THROW(cx_bn_unlock());            

            // jac_p_bn_t acc;
            // pallas_jac_alloc(&acc);

            // // jac_p_bn_t b;
            // // pallas_jac_init(&b, &SPEND_AUTH_GEN);

            // // // for (uint16_t i = 0; i < 255; i++) {
            // // //     pallas_double_jac(&acc, M);
            // // //     if (i == 253)
            // // //         pallas_add_jac(&acc, &acc, &b, M);
            // // // }

            // pallas_jac_init(&acc, &SPEND_AUTH_GEN);
            // // pallas_add_jac(&acc, &acc, &b, M);
            // pallas_double_jac(&acc, M);

            // pallas_jac_export(&r, &acc);
            // CX_THROW(cx_bn_unlock());

            // pallas_to_bytes(res, &r);

            // fv_t x;
            // memset(&x, 0, 32);
            // x[31] = i;

            // pallas_base_mult(&r, &SPEND_AUTH_GEN, (fv_t *)&ask);
            // memmove(res, &r, 96);
            // pallas_to_bytes(res, &r);
        }
        CATCH_OTHER(e) {
            error = e;
        }
        FINALLY {
        }
    }
    END_TRY;
    if (error != 0) return io_send_sw(error);
    return helper_send_response_bytes((uint8_t *)&r, 96);
}

// 628CF615D21CF30D41826ED13D4D4A1D3C9B8640E76AE52103E94683DDB8FB24
// a85a53bfdb32c3e519768fbc054e0f5ff7ad48a0e58a276078b38b2464f8dd15

// 24fbb8dd8346e90321e56ae740869b3c1d4a4d3dd16e82410df31cd215f68c62cc14620a8efd68b6991e6ff8f95caa2a47a65e21ccc02a89a93e951e2a6a777e
// 24FBB8DD8346E90321E56AE740869B3C1D4A4D3DD16E82410DF31CD215F68C62CC14620A8EFD68B6991E6FF8F95CAA2A47A65E21CCC02A89A93E951E2A6A777E

// a693b6030117ea11459e9095918dc762274efb2511ca5fa400471c7cb8706a5a32969525df9c14c452acacb35907e78f96fd35edb793d942cff62c6ad70cc066
// 0x1976e3e92c88e6df8a700c855be3715e23e947f761754f2a09a02e9a6ba996f1

// A693B6030117EA11459E9095918DC762274EFB2511CA5FA400471C7CB8706A5A32969525DF9C14C452ACACB35907E78F96FD35EDB793D942CFF62C6AD70CC066
// 5A6A70B87C1C4700A45FCA1125FB4E2762C78D9195909E4511EA170103B693A6

