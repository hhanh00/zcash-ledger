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
#include <os.h>       // sprintf
#include "sinsemilla.h"
#include "pallas.h"

#define min(a, b) ((a) > (b) ? (b) : (a))

#ifdef ORCHARD

void init_sinsemilla(sinsemilla_state_t *state, jac_p_t *Q) {
    memset(state, 0, sizeof(sinsemilla_state_t));
    memmove(&state->p, Q, sizeof(jac_p_t));
}

void hash_sinsemilla(sinsemilla_state_t *state, uint8_t *data, size_t data_bit_len) {
    size_t byte_length = (data_bit_len + 7) / 8;

    for (size_t i = 0; i < byte_length; i++) {
        uint8_t byte = data[i];
        // process 8 bits at a time, until the last byte if it is not an full byte
        int bits_to_process = (i == byte_length - 1 && data_bit_len % 8 != 0) ? data_bit_len % 8 : 8;

        while (bits_to_process > 0) {
            // number of bits needed to fill up our current pack
            int bits_to_add = min(10 - state->bits_in_pack, bits_to_process);

            // mask that extracts 'bits_to_add' bits
            uint8_t mask = ((1 << bits_to_add) - 1);
            // take these bits in LE from the byte input
            uint8_t bits = byte & mask; 
            // add them in front of the current pack
            state->current_pack |= (bits << state->bits_in_pack);

            // shift the input byte to remove the extracted bits
            byte >>= bits_to_add;

            // update our counts
            state->bits_in_pack += bits_to_add;
            bits_to_process -= bits_to_add;

            // if the pack is full, emit it
            if (state->bits_in_pack == 10) {
                // PRINTF("Pack %04X\n", state->current_pack);
                jac_p_t S;
                sinsemilla_S(&S, state->current_pack);
                jac_p_t acc;
                pallas_copy_jac(&acc, &state->p);
                pallas_add_assign(&state->p, &S);
                pallas_add_assign(&state->p, &acc);
                state->bits_in_pack = 0;
                state->current_pack = 0;
            }
        }
    }
}

void finalize_sinsemilla(sinsemilla_state_t *state, uint8_t *hash) {
    if (state->bits_in_pack > 0) {
        // PRINTF("Pack 0x%04X\n", state->current_pack);
        jac_p_t S;
        sinsemilla_S(&S, state->current_pack);
        jac_p_t acc;
        pallas_copy_jac(&acc, &state->p);
        pallas_add_assign(&state->p, &S);
        pallas_add_assign(&state->p, &acc);
        if (hash)
            pallas_to_bytes(hash, &state->p);
        state->bits_in_pack = 0;
    }
}

void init_commit(sinsemilla_state_t *state, uint8_t *perso_M, size_t perso_len) {
    jac_p_t Q;
    hash_to_curve(&Q, 
        (uint8_t *)"z.cash:SinsemillaQ", 18,
        perso_M, perso_len);

    init_sinsemilla(state, &Q);
}

void finalize_commit(sinsemilla_state_t *state, uint8_t *perso_r, size_t perso_len, fv_t *v, uint8_t *hash) {
    finalize_sinsemilla(state, NULL);
    jac_p_t R;
    hash_to_curve(&R, 
        perso_r, perso_len,
        NULL, 0);
    jac_p_t r;
    pallas_base_mult(&r, &R, v);
    pallas_add_assign(&r, &state->p);
    pallas_to_bytes(hash, &r);
    swap_endian(hash, 32);
    hash[0] &= 0x7F;
}

void sinsemilla_S(jac_p_t *S, uint32_t i) {
    hash_to_curve(S, 
        (uint8_t *)"z.cash:SinsemillaS", 18,
        (uint8_t *)&i, 4);
}

#endif
