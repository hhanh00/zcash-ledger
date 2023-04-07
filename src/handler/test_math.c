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
#include "../tx.h"
#include "../crypto/txid.h"

const uint8_t ADDRESS[] = {0xc8, 0x20, 0xed, 0x6c, 0xd3, 0x99, 0x1d, 0xbc, 0x7c, 0xa0, 0x4b,
                           0xba, 0x22, 0x7b, 0xe6, 0xa4, 0xc3, 0x35, 0xf3, 0x88, 0xa1, 0x08,
                           0x93, 0x20, 0x11, 0xa6, 0xd7, 0x12, 0x4c, 0x22, 0x5e, 0x1d, 0xf6,
                           0x23, 0x04, 0x90, 0x34, 0xdb, 0x83, 0x4e, 0x83, 0xd0, 0xb4};
const uint8_t RSEED[] = { 0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37, 0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c, 0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86 };
const uint64_t VALUE = 30897000;                          

int handler_test_math() {
    int error = 0;
    BEGIN_TRY {
        TRY {
            calc_cmu(ADDRESS, RSEED, VALUE);
            // init_tx();
            // add_t_input_amount(1000000);
            // t_out_t tout1 = {
            //     .amount = 100000,
            //     .address_type = 0,
            //     .address_hash = {0xcb, 0xe3, 0x57, 0x94, 0x75, 0xf2, 0xc7, 0xed, 0x1f, 0xa8,
            //                      0x65, 0x03, 0x4f, 0x75, 0xb6, 0x8c, 0x0f, 0x23, 0xaa, 0x04}};
            // add_t_output(&tout1);
            // t_out_t tout2 = {
            //     .amount = 100000,
            //     .address_type = 0,
            //     .address_hash = {0xcb, 0xe3, 0x57, 0x94, 0x75, 0xf2, 0xc7, 0xed, 0x1f, 0xa8,
            //                      0x65, 0x03, 0x4f, 0x75, 0xb6, 0x8c, 0x0f, 0x23, 0xaa, 0x04}};
            // add_t_output(&tout2);
        }
        CATCH_OTHER(e) {
            error = e;
        }
        FINALLY {
        }
    }
    END_TRY;
    if (error != 0) return io_send_sw(error);
    return helper_send_response_bytes((u_int8_t *) &G_context.address, 78);
    // return helper_send_response_bytes((u_int8_t *)&G_context.exp_sk_info.out, 160);
}
