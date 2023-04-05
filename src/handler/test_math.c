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

#include "get_fvk.h"
#include "../globals.h"
#include "../types.h"
#include "../io.h"
#include "../sw.h"
#include "../common/buffer.h"
#include "../ui/display.h"
#include "../helper/send_response.h"
#include "../crypto/txid.h"

int handler_test_math() {
    int error = 0;
    BEGIN_TRY {
        TRY {
            init_tx_v5(2039570);
            t_in_t tin = {
                .index = 0,
                .prev_tx_hash = { 0xb9, 0x96, 0x31, 0x92, 0xa7, 0x76, 0x5d, 0x7e, 0xad, 0x70, 0x4d, 0x6d, 0xe1, 0xa4, 0xc1, 0x28, 0x00, 0x91, 0x6a, 0xe3, 0x54, 0x4e, 0x9c, 0x56, 0x6e, 0xd5, 0xc2, 0xe0, 0x93, 0x8a, 0xd1, 0xd3 },
                .amount = 1000000,
            };
            add_transparent_input(&tin);
            t_out_t tout1 = {
                .amount = 100000,
                .pkh = { 0xcb, 0xe3, 0x57, 0x94, 0x75, 0xf2, 0xc7, 0xed, 0x1f, 0xa8, 0x65, 0x03, 0x4f, 0x75, 0xb6, 0x8c, 0x0f, 0x23, 0xaa, 0x04 },
            };
            add_transparent_output(&tout1);
            t_out_t tout2 = {
                .amount = 899000,
                .pkh = { 0xcb, 0xe3, 0x57, 0x94, 0x75, 0xf2, 0xc7, 0xed, 0x1f, 0xa8, 0x65, 0x03, 0x4f, 0x75, 0xb6, 0x8c, 0x0f, 0x23, 0xaa, 0x04 },
            };
            add_transparent_output(&tout2);

            confirm_tx();

            sign_transparent_input(&tin);
        }
        CATCH_OTHER(e) {
            error = e;
        }
        FINALLY {}
    }
    END_TRY;
    if (error != 0) return io_send_sw(error);
    return helper_send_response_bytes((u_int8_t *)&G_context.address, 78);
    // return helper_send_response_bytes((u_int8_t *)&G_context.exp_sk_info.out, 160);
}
