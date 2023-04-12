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
#include "tx.h"
#include "../crypto/txid.h"

const uint8_t ADDRESS[] = {0xc8, 0x20, 0xed, 0x6c, 0xd3, 0x99, 0x1d, 0xbc, 0x7c, 0xa0, 0x4b,
                           0xba, 0x22, 0x7b, 0xe6, 0xa4, 0xc3, 0x35, 0xf3, 0x88, 0xa1, 0x08,
                           0x93, 0x20, 0x11, 0xa6, 0xd7, 0x12, 0x4c, 0x22, 0x5e, 0x1d, 0xf6,
                           0x23, 0x04, 0x90, 0x34, 0xdb, 0x83, 0x4e, 0x83, 0xd0, 0xb4};
const uint8_t RSEED[] = { 0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37, 0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c, 0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86 };
const uint64_t VALUE = 30897000;                          

const uint8_t HEADER_DIGEST[32] = {0xff, 0x10, 0x75, 0xf8, 0xa9, 0x29, 0x4f, 0xb5, 0x27, 0x60, 0xfe, 0x87, 0xfc, 0x51, 0x4d, 0xad, 0xcb, 0x79, 0x7f, 0x2a, 0xd2, 0x68, 0x82, 0x5f, 0x4a, 0x79, 0xbd, 0x35, 0x51, 0x11, 0x09, 0xd8};



int handler_test_math() {
    int error = 0;
    BEGIN_TRY {
        TRY {
            init_tx((uint8_t *)HEADER_DIGEST);
            // add_t_input_amount: CBDC27BD0946A43495971D2887D6DD1EB4BFDE3807B0F74E195E9DC17D4EB3F0
            change_stage(1);
            t_out_t tout1 = {
                .address_type = 0,
                .address_hash = { 0x84, 0x90, 0x99, 0x64, 0xc1, 0x83, 0x0c, 0x07, 0x92, 0xcb, 0x69, 0x8e, 0x25, 0x40, 0x46, 0x9b, 0x0c, 0x9e, 0x03, 0x22 },
                .amount = 1700000,
            };
            add_t_output(&tout1); // F0DC93DBB264001E8E8A77FBA1571EE03CAEEA2B6107C0EF19A3C9BE1EC9956A
            change_stage(2);
            s_out_t sout1 = {
                .address = { 0xc8, 0x20, 0xed, 0x6c, 0xd3, 0x99, 0x1d, 0xbc, 0x7c, 0xa0, 0x4b, 0xba, 0x22, 0x7b, 0xe6, 0xa4, 0xc3, 0x35, 0xf3, 0x88, 0xa1, 0x08, 0x93, 0x20, 0x11, 0xa6, 0xd7, 0x12, 0x4c, 0x22, 0x5e, 0x1d, 0xf6, 0x23, 0x04, 0x90, 0x34, 0xdb, 0x83, 0x4e, 0x83, 0xd0, 0xb4 },
                .amount = 1200000,
                .enc = { 0xfd, 0xcc, 0xdc, 0xf5, 0x40, 0x41, 0x32, 0xe8, 0xf0, 0x16, 0x1e, 0xed, 0x6c, 0x20, 0xb8, 0xe5, 0xdf, 0x9b, 0xd7, 0x41, 0xcd, 0x39, 0xcd, 0xae, 0x1d, 0xc0, 0x4d, 0x13, 0xb0, 0x4e, 0xaf, 0xd7, 0xa5, 0x25, 0x32, 0x72, 0xae, 0xa7, 0x4d, 0xd4, 0xe1, 0x59, 0x3f, 0xdb, 0xfb, 0x00, 0x35, 0x49, 0x34, 0xaf, 0xaa, 0x14},
                .epk = { 0x6d, 0xdf, 0x62, 0x26, 0xd5, 0xdc, 0xc0, 0x00, 0x4b, 0xf7, 0x6a, 0x33, 0x1e, 0xbd, 0x5c, 0xac, 0xb7, 0x15, 0x09, 0xdf, 0xe2, 0xf6, 0x83, 0x7a, 0x96, 0xef, 0xf5, 0x31, 0x89, 0xc2, 0x07, 0x2d },
                .idx = 0,
            };         
            add_s_output(&sout1); // 643B9C6971EB6DE858D81D9B225A53E66F77BEFBAB2F01805525C553A77F952A
            s_out_t sout2 = {
                .address = { 0xc8, 0x20, 0xed, 0x6c, 0xd3, 0x99, 0x1d, 0xbc, 0x7c, 0xa0, 0x4b, 0xba, 0x22, 0x7b, 0xe6, 0xa4, 0xc3, 0x35, 0xf3, 0x88, 0xa1, 0x08, 0x93, 0x20, 0x11, 0xa6, 0xd7, 0x12, 0x4c, 0x22, 0x5e, 0x1d, 0xf6, 0x23, 0x04, 0x90, 0x34, 0xdb, 0x83, 0x4e, 0x83, 0xd0, 0xb4 },
                .amount = 30897000,
                .enc = { 0x07, 0x24, 0xb7, 0xcc, 0xa8, 0xb3, 0xfc, 0x8b, 0x58, 0x82, 0xa8, 0xb7, 0xfc, 0x69, 0x94, 0xda, 0x34, 0x73, 0x8f, 0x03, 0x40, 0x6b, 0x8c, 0xcf, 0x7e, 0x8b, 0x85, 0x5d, 0x3d, 0x77, 0x54, 0xc9, 0x13, 0xe2, 0x7c, 0x1e, 0x40, 0x9a, 0xd5, 0xc9, 0x6b, 0xef, 0x62, 0x0c, 0x67, 0x12, 0xff, 0xed, 0xad, 0x61, 0x82, 0x63},
                .epk = {0x50, 0x21, 0x9a, 0x64, 0x97, 0x36, 0x60, 0x1d, 0x90, 0x01, 0x4b, 0x86, 0x56, 0x93, 0xef, 0x95, 0x3a, 0xa6, 0xc7, 0x17, 0x10, 0x3e, 0x33, 0x74, 0xe7, 0x10, 0xe0, 0x9e, 0xc7, 0x14, 0x09, 0x97},
                .idx = 1,
            };         
            add_s_output(&sout2); // 18B4F8C981985EEF0AF5E8BDCC866EAAE13E46047077F262D51F192C77DBC121
            change_stage(3); // S OUT C F757CD00F0D4AAB345B99C1ABB5FCA6CCF3D74B620C3C2621C66FD13593580A8

            t_proofs_t t_proof = {
                .prevouts_sig_digest = {0xa0, 0x4b, 0x16, 0x83, 0x4d, 0xc9, 0x39, 0xcc, 0xf6, 0x32, 0xd1, 0x5d, 0xdd, 0xaa, 0x6b, 0xca, 0xed, 0x25, 0x3d, 0x12, 0x06, 0x8d, 0xca, 0x16, 0x9f, 0xbd, 0x28, 0xbc, 0x40, 0x3c, 0xf3, 0xba},
                .sequence_sig_digest = {0x3a, 0x00, 0x33, 0x33, 0x66, 0x03, 0x23, 0x50, 0x01, 0x74, 0x24, 0x38, 0x23, 0x8d, 0x71, 0x3c, 0x09, 0xc1, 0xc5, 0x5b, 0xf6, 0x7b, 0xd2, 0x0b, 0x80, 0x80, 0x5a, 0xea, 0x0b, 0x46, 0xeb, 0xa5},
                .scriptpubkeys_sig_digest = {0xf0, 0xdc, 0x93, 0xdb, 0xb2, 0x64, 0x00, 0x1e, 0x8e, 0x8a, 0x77, 0xfb, 0xa1, 0x57, 0x1e, 0xe0, 0x3c, 0xae, 0xea, 0x2b, 0x61, 0x07, 0xc0, 0xef, 0x19, 0xa3, 0xc9, 0xbe, 0x1e, 0xc9, 0x95, 0x6a},
            };
            set_t_merkle_proof(&t_proof);

            s_proofs_t s_proof = {
                .sapling_spends_digest = {0xc3, 0x11, 0xd9, 0x85, 0xa9, 0x17, 0x36, 0x9a, 0x46, 0xdb, 0xba, 0x2c, 0xf5, 0x2c, 0x25, 0xec, 0xdd, 0xb4, 0x18, 0xf8, 0x80, 0xb6, 0xb6, 0xdb, 0xcf, 0x5a, 0x04, 0x66, 0xfd, 0x83, 0x8d, 0x8d},
                .sapling_outputs_memos_digest = {0x7a, 0x29, 0x52, 0x70, 0x51, 0x13, 0x2d, 0x98, 0x1a, 0xd6, 0x64, 0xb6, 0x08, 0xc7, 0x14, 0x91, 0xdd, 0xde, 0x41, 0x9b, 0x6a, 0x51, 0xa5, 0x68, 0x7f, 0xb2, 0x5e, 0x75, 0xb9, 0xf1, 0xf5, 0xf5},
                .sapling_outputs_noncompact_digest = {0xe3, 0x0a, 0x49, 0x2a, 0xb3, 0x4e, 0x8b, 0xf2, 0xcd, 0xd9, 0x10, 0x82, 0x48, 0x7c, 0x84, 0xe7, 0x6f, 0xe6, 0x93, 0xfe, 0xba, 0x0c, 0x71, 0x62, 0x18, 0x49, 0x72, 0x05, 0xf7, 0x6e, 0x71, 0x21},
            };
            set_s_merkle_proof(&s_proof);

            set_sapling_net(1701000); // opposite sign from tx.json

            uint8_t txid[32];
            sighash(txid, NULL); // 7FE39578B31FA4342A8DDCD597F45F3A27BFFE262805F2F79216B22F656C545B
                                 // 7fe39578b31fa4342a8ddcd597f45f3a27bffe262805f2f79216b22f656c545b



            // cx_blake2b_t tx_t_hasher;
            // cx_hash_t *ph = (cx_hash_t *)&tx_t_hasher;
            // uint8_t transparent_hash[32];
            // cx_blake2b_init2_no_throw(&tx_t_hasher, 256, NULL, 0, (uint8_t *)"ZTxIdOrchardHash", 16);
            // cx_hash(ph, CX_LAST, NULL, 0, transparent_hash, 32);
            // PRINTF("ORCHARD: %.*H\n", 32, transparent_hash);

            // uint8_t cmu[32];
            // calc_cmu(cmu, ADDRESS, RSEED, VALUE);
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
