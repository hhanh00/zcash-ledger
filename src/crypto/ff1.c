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
#include <lcx_aes.h>
#include <lcx_math.h>

#include "fr.h"

#include "globals.h"

/* ff1-aes256

K is diversifier key [u8;32]
radix = 2
n = 88
u = 44, v = 44
A is [0..44 bits] of diversifier index 
B is [0..88] = 6 bytes 
A | B = DI, DI[5] is split between A and B, hi -> A, lo -> B

A[0] = DI[0] >> 4 
A[1] = DI[0] & 0F << 4 | DI[1] >> 4
...
A[5] = DI[4] & 0F << 4 | DI[5] >> 4
B[0] = DI[5] & 0F
B[1] = DI[6]
...
B[5] = DI[10]

b = 6, 2^6 = 64 > v
d = 12
P is  [ 1, 2, 1, 0, 0, 2, 10, 44, 0, 0, 0, 88, 0, 0, 0, 0 ]
loop i = 0 to 10
    Q is  [ 0, 0, 0, 0, 0, 0, 0, 0, 0, i, B[0..6]] = 16 bytes
    R = AES_K(P|Q) in CBC mode with IV = 0
    S = R[0..12]
    C = A + S mod (2^11) 
    A = B
    B = C

Res = A | B
*/

int ff1(uint8_t *d, const uint8_t *dk, uint8_t *di) {
    int error = 0;
    uint8_t a[6];
    uint8_t b[6];

    // split di into a|b
    a[0] = di[0] >> 4;
    b[0] = di[5] & 0xF;
    for (int i = 1; i < 6; i++) {
        a[i] = di[i-1] << 4 | di[i] >> 4;
        b[i] = di[i+5];
    }

    cx_aes_key_t aes_key;

    for (int i = 0; i < 10; i++) {
        cx_aes_init_key_no_throw(dk, 32, &aes_key);
        uint8_t R[16];
        memset(R, 0, 16);
        size_t out_len = 16;

        uint8_t P[16];
        memset(P, 0, 16);
        P[0] = 1;
        P[1] = 2;
        P[2] = 1;
        P[5] = 2;
        P[6] = 10;
        P[7] = 44;
        P[11] = 88;

        error = cx_aes_iv_no_throw(&aes_key, CX_ENCRYPT | CX_PAD_NONE | CX_CHAIN_CBC, (uint8_t *)R, 16, 
            (uint8_t *)P, 16, (uint8_t *)R, &out_len);

        memset(P, 0, 16);
        P[9] = i;
        memmove(&P[10], b, 6);
        error = cx_aes_iv_no_throw(&aes_key, CX_ENCRYPT | CX_PAD_NONE | CX_CHAIN_CBC | CX_LAST, (uint8_t *)R, 16, 
            (uint8_t *)P, 16, (uint8_t *)R, &out_len);
        memmove(d, R, 16);

        uint8_t c[6];
        cx_math_add_no_throw(c, a, R + 6, 6); // skip first d-6
        c[0] &= 0x0F; // modulo 5.5 bytes

        memmove(a, b, 6);
        memmove(b, c, 6);
    }

    memmove(d, a, 6);
    memmove(d+6, b, 5);

    // Put a|b into d
    memset(d, 0, 11);
    for (int i = 0; i < 5; i++) {
        d[i] = a[i] << 4 | a[i+1] >> 4;
        d[i+6] = b[i+1];
    }
    d[5] = a[5] << 4 | (b[0] & 0x0F);

    // reverse each byte bit by bit
    for (int i = 0; i < 11; i++) {
        uint8_t b = d[i];
        b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
        b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
        b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
        d[i] = b;
    }

    return error;
}
