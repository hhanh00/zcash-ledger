/*******************************************************************************
*   Ledger Nano S - Secure firmware
*   (c) 2022 Ledger
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
********************************************************************************/

#include <stdint.h>   // uint*_t
#include <string.h>   // memset, explicit_bzero
#include <ox.h>
#include <cx.h>
#include <lcx_hash.h>
#include <lcx_blake2.h>
#include "f4jumble.h"

static uint8_t hash[64];

void G(cx_blake2b_t *hash_ctx, uint8_t round, uint8_t *m, size_t len) {
    uint8_t perso[16];
    memmove(perso, "UA_F4Jumble_G", 13);
    perso[13] = round;
    memset(perso + 14, 0, 2);
    cx_blake2b_init2_no_throw(hash_ctx, 512, NULL, 0, perso, 16);
    cx_hash((cx_hash_t *)hash_ctx, CX_LAST, m, len, hash, 64);
    PRINTF("G: %.*H\n", 64, hash);
}

void H(cx_blake2b_t *hash_ctx, uint8_t round, uint8_t *m, size_t len) {
    uint8_t perso[16];
    memmove(perso, "UA_F4Jumble_H", 13);
    perso[13] = round;
    memset(perso + 14, 0, 2);
    cx_blake2b_init2_no_throw(hash_ctx, 512, NULL, 0, perso, 16);
    cx_hash((cx_hash_t *)hash_ctx, CX_LAST, m, len, hash, 64);
    PRINTF("H: %.*H\n", 64, hash);
}

static int xor(uint8_t *dst, uint8_t *src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dst[i] ^= src[i];
    }
}

int f4jumble(uint8_t *message, size_t len) {
    // This implementation only supports length 128
    if (len != 128) return CX_INVALID_PARAMETER;

    cx_blake2b_t hash_ctx;

    size_t half_len = 64;
    uint8_t *left = message;
    uint8_t *right = message + half_len;

    G(&hash_ctx, 0, left, half_len);
    xor(right, hash, half_len);
    PRINTF("R: %.*H\n", half_len, right);
    H(&hash_ctx, 0, right, half_len);
    xor(left, hash, half_len);
    G(&hash_ctx, 1, left, half_len);
    xor(right, hash, half_len);
    H(&hash_ctx, 1, right, half_len);
    xor(left, hash, half_len);

    return 0;
}

