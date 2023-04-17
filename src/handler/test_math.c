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

int handler_test_math() {
    int error = 0;
    BEGIN_TRY {
        TRY {
            simple_point_test();
            
            fq_t d2;

            // cx_math version
            // memmove(&d2, fq_D, 32);
            // for (int i = 0; i < 10000; i++) {
            //     fq_square(&d2);
            // }

            // bn version
            // cx_bn_lock(32, 0);
            // cx_bn_t d, m;
            // cx_bn_alloc_init(&d, 32, fq_D, 32);
            // cx_bn_alloc_init(&m, 32, fq_m, 32);
            // for (int i = 0; i < 10000; i++) {
            //     cx_bn_mod_mul(d, d, d, m);
            // }
            // cx_bn_export(d, (uint8_t *)&d2, 32);
            // cx_bn_unlock();

            // cx_bn_mont_ctx_t ctx;
            // cx_bn_t d, m;
            // cx_bn_lock(32, 0);
            // cx_bn_alloc_init(&m, 32, fq_m, 32);
            // cx_mont_init(&ctx, m);
            // cx_bn_alloc_init(&d, 32, fq_D, 32);
            // cx_mont_to_montgomery(d, d, &ctx);
            // for (int i = 0; i < 10000; i++) {
            //     cx_mont_mul(d, d, d, &ctx);
            // }
            // cx_mont_from_montgomery(d, d, &ctx);
            // cx_bn_export(d, (uint8_t *)&d2, 32);
            // cx_bn_unlock();
        }
        CATCH_OTHER(e) {
            error = e;
        }
        FINALLY {
        }
    }
    END_TRY;
    if (error != 0) return io_send_sw(error);
    return helper_send_response_bytes(NULL, 0);
}
