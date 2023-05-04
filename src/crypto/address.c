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

#include "bech32.h"
#include "../common/base58.h"

#include "globals.h"

void to_address_bech32(char *address, uint8_t *d, uint8_t *pk_d) {
    uint8_t buffer[70];
    uint8_t data[43];
    memmove(data, d, 11);
    memmove(data + 11, pk_d, 32);
    size_t buffer_len = 0;
    convert_bits(buffer, &buffer_len, 5, data, 43, 8, 1);
    bech32_encode(address, "zs", buffer, buffer_len, BECH32_ENCODING_BECH32);
}

/**
 * out_address must has length 80 bytes at least
*/
void to_t_address(char *out_address, uint8_t *kh) { 
    uint8_t address[26];
    uint8_t hash[32];
    cx_sha256_t sha_hasher;

    address[0] = 0x1C;
    address[1] = 0xB8;
    memmove(address + 2, kh, 20);
    cx_sha256_init_no_throw(&sha_hasher);
    cx_hash_no_throw((cx_hash_t *)&sha_hasher, CX_LAST, address, 22, hash, 32);
    cx_sha256_init_no_throw(&sha_hasher);
    cx_hash_no_throw((cx_hash_t *)&sha_hasher, CX_LAST, hash, 32, hash, 32); // dsha
    memmove(address + 22, hash, 4);
    memset(out_address, 0, 80);
    base58_encode(address, 26, out_address, 80);
} 

