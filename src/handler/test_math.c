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

const uint8_t data[] = { 
    0xB3, 0x15, 0x69, 0x3B, 0x48, 0x6D, 0x4D, 0x3C, 0xD8, 0xE4, 0x25, 0x6E, 0x8C, 0x37, 0xCA, 0x4E, 0x8E, 0xC3, 0x67, 0xE4, 0xD9, 0x5D, 0x5C, 0x31, 0x46, 0x25, 0xDC, 0x7B, 0x44, 0xB5, 0x7E, 0xA2, 0xCA, 0x18, 0xFD, 0xCF, 0xF5, 0x87, 0x19, 0x06, 0xF4, 0x23, 0x8F
};

int handler_test_math() {
    int error = 0;
    jac_p_t r;
    BEGIN_TRY {
        TRY {
            // hash_to_curve(&r, "Domain", 6, "hello", 5);

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
    return helper_send_response_bytes((uint8_t *)&r, 32);
}
