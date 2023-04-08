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

#include "../tx.h"
#include "fr.h"
#include "jubjub.h"
#include "txid.h"
#include "ph.h"
#include "prf.h"

#include "os.h"

int calc_cmu(uint8_t *address, uint8_t *rseed, uint64_t value) {
    int error = 0;
    PRINTF("Address: %.*H\n", 43, address);
    PRINTF("Rseed: %.*H\n", 32, rseed);
    PRINTF("Value: %.*H\n", 8, (uint8_t *)&value);
    
    uint8_t gd_hash[32];
    jubjub_hash(gd_hash, address, 11);
    extended_niels_point_t g_d_n;
    error = extn_from_bytes(&g_d_n, gd_hash);
    if (error) return error;
    extended_point_t g_d;
    ext_set_identity(&g_d);
    ext_add(&g_d, &g_d_n);
    ext_to_bytes(gd_hash, &g_d);
    PRINTF("G_d: %.*H\n", 32, gd_hash);

    uint8_t rcm[64];
    memmove(rcm, rseed, 32);
    prf_expand_seed(rcm, 4);
    fr_from_wide(rcm);
    PRINTF("rcm: %.*H\n", 32, rcm);

    pedersen_hash_cmu(value, gd_hash, address + 11, (fr_t *)rcm);
    return error;
}

void pedersen_hash_cmu(uint64_t value, uint8_t *g_d, uint8_t *pk_d, fr_t *rcm) {
    // we have 6 bits of personalization 
    // value has 64 bits
    // g_d and pk_d have 256 bits
    // total 582 bits = 194 chunks
    // each generator is for 63 chunks
    // therefore we need 4 generators
    
    uint8_t buffer[73]; // 1 + 8 + 32 + 32
    memset(buffer, 0, sizeof(buffer));
    memmove(buffer, (uint8_t *)&value, 8);
    memmove(buffer + 8, (uint8_t *)g_d, 32);
    memmove(buffer + 40, (uint8_t *)pk_d, 32);
    // shift by 6 bits to make room for the personalization bits
    uint8_t carry = 0;
    for (int i = 0; i < 72; i++) {
        uint8_t c = (buffer[i] & 0xFC) >> 2; // 6 high bits
        buffer[i] = (buffer[i] << 6) | carry;
        carry = c;
    }
    buffer[72] = carry;
    buffer[0] |= 0x3F;

    PRINTF("PH BUFFER: %.*H\n", 73, buffer);

    extended_point_t pedersen_hash;
    ext_set_identity(&pedersen_hash);
    extended_point_t tmp_p;
    extended_niels_point_t tmp_pn;

    fr_t acc, cur, tmp;
    memset(&acc, 0, 32);
    memmove(&cur, fq_1, 32);

    uint8_t byte_offset = 0;
    uint8_t bit_offset = 0;
    for (uint8_t chunk = 0; chunk < 194; chunk++) {
        uint16_t v = buffer[byte_offset] | (uint16_t)buffer[byte_offset + 1] << 8;
        uint8_t n = (v >> bit_offset) & 0x07;

        memmove(&tmp, &cur, 32);
        if ((n & 1) != 0) {
            fr_add(&tmp, &tmp, &cur);
        }
        fr_double(&cur);
        if ((n & 2) != 0) {
            fr_add(&tmp, &tmp, &cur);
        }
        if ((n & 4) != 0) {
            fr_negate(&tmp);
        }
        // PRINTF("PH TMP: %.*H\n", 32, tmp);
        fr_add(&acc, &acc, &tmp);
        fr_double(&cur);
        fr_double(&cur);
        fr_double(&cur);

        bit_offset += 3;
        if (bit_offset >= 8) {
            bit_offset -= 8;
            byte_offset++;
        }

        if (chunk % 63 == 62) {
            PRINTF("PH ACC: %.*H\n", 32, acc);

            ext_base_mult(&tmp_p, &PEDERSEN_HASH_GENS[chunk / 63], &acc);
            ext_to_niels(&tmp_pn, &tmp_p);
            ext_add(&pedersen_hash, &tmp_pn);

            memset(&acc, 0, 32);
            memmove(&cur, fq_1, 32);
        }
    }

    PRINTF("PH ACC: %.*H\n", 32, acc);
    ext_base_mult(&tmp_p, &PEDERSEN_HASH_GENS[3], &acc);
    ext_to_niels(&tmp_pn, &tmp_p);
    ext_add(&pedersen_hash, &tmp_pn);

    ext_base_mult(&tmp_p, &CMU_RAND_GEN, rcm);
    ext_to_niels(&tmp_pn, &tmp_p);
    ext_add(&pedersen_hash, &tmp_pn);

    uint8_t hash[32];
    ext_to_u(hash, &pedersen_hash);
    PRINTF("PH: %.*H\n", 32, hash);
}
