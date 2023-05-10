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
#include <ox_bn.h>

#include "fr.h"

#include "globals.h"

/* ff1-aes256

[NIST Recommendation](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)

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

/**
 * Format Preserving Encryption on the diversifier index (di)
 * 
 * It is essentially performing a permutation of the input
 * using the diversifier key (dk)
 * 
 * The output (d) has the same size as di
 * For a given di & dk, the output d is the same
 * (no IV)
*/
/// @brief Performs FF1 in place
/// @param dk 
/// @param di 
void ff1_inplace(const uint8_t *dk, uint8_t *di) {
    // data should be in radix 2, we flip bit per bit
    // while keeping the byte endianess
    swap_bit_endian(di, 11); 

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

        // technically, P is constant and the first output block of AES is going to be
        // the same across the 10 rounds
        // but it does not make much difference in performance and the code is simplier like this
        cx_aes_iv_no_throw(&aes_key, CX_ENCRYPT | CX_PAD_NONE | CX_CHAIN_CBC, (uint8_t *)R, 16, 
            (uint8_t *)P, 16, (uint8_t *)R, &out_len);

        memset(P, 0, 16);
        P[9] = i;
        memmove(&P[10], b, 6);
        // block depends on the round number and b
        cx_aes_iv_no_throw(&aes_key, CX_ENCRYPT | CX_PAD_NONE | CX_CHAIN_CBC | CX_LAST, (uint8_t *)R, 16, 
            (uint8_t *)P, 16, (uint8_t *)R, &out_len);

        // we need to take 12 bytes because d = 12 in our case
        // we know we only need at most 6 bytes because n/2 = 5.5
        // skip first d-6
        // same as cx_math_add_no_throw(c, a, R + 6, 6) but without locking BN
        // we want 6 byte BE, the closest is 8 byte LE therefore do some byte manipulation
        uint64_t ia; memset(&ia, 0, 8); memmove((uint8_t *)&ia + 2, a, 6); swap_endian((uint8_t *)&ia, 8);
        uint64_t iR; memset(&iR, 0, 8); memmove((uint8_t *)&iR + 2, R+6, 6); swap_endian((uint8_t *)&iR, 8);
        uint64_t ic = ia + iR; swap_endian((uint8_t *)&ic, 8);
        uint8_t *c = (uint8_t *)&ic;
        c[2] &= 0x0F; // modulo 5.5 bytes

        // swap a & b and replace with c
        memmove(a, b, 6);
        memmove(b, c+2, 6);
    }

    // stitch the result back
    // it's the reverse of the split we did above
    memset(di, 0, 11);
    for (int i = 0; i < 5; i++) {
        di[i] = a[i] << 4 | a[i+1] >> 4;
        di[i+6] = b[i+1];
    }
    di[5] = a[5] << 4 | (b[0] & 0x0F);
    swap_bit_endian(di, 11);
}
