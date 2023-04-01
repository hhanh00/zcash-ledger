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

#include "key.h"
#include "prf.h"
#include "fr.h"
#include "ff1.h"
#include "jubjub.h"
#include "blake2s.h"

#include "globals.h"

int crypto_derive_spending_key(expanded_spending_key_t *exp_sk) {
    uint32_t bip32_path[5] = {0x8000002C, 0x80000085, 0x80000000, 0, 0};

    int error = 0;
    uint8_t spending_key[32];

    BEGIN_TRY {
        TRY {
            // derive the seed with bip32_path
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       bip32_path,
                                       5,
                                       spending_key,
                                       NULL);

            // set spending key to 0 for testing
            memset(spending_key, 0, 32);                                       

            uint8_t xsk[64];
            memmove(xsk, spending_key, 32); // ask
            error = prf_expand_seed(xsk, 0);
            if (error) return error;
            error = fr_from_wide(xsk);
            if (error) return error;
            memmove(&exp_sk->ask, xsk, 32);

            memmove(xsk, spending_key, 32); // nsk
            error = prf_expand_seed(xsk, 1);
            if (error) return error;
            error = fr_from_wide(xsk);
            if (error) return error;
            memmove(&exp_sk->nsk, xsk, 32);

            memmove(xsk, spending_key, 32); // ovk
            error = prf_expand_seed(xsk, 2);
            if (error) return error;
            memmove(&exp_sk->ovk, xsk, 32);

            // dk - diversifier key
            memmove(xsk, spending_key, 32); // ovk
            error = prf_expand_seed(xsk, 0x10);
            if (error) return error;
            memmove(&exp_sk->dk, xsk, 32);

            uint8_t di[11];
            memset(di, 0, 11);

            extended_point_t gd_p;
            for (uint32_t i = 0; ; i++) {
                memset(di, 0, 11);
                memmove(di, &i, 4);

                ff1((uint8_t *)&exp_sk->d, (uint8_t *)&exp_sk->dk, di);

                uint8_t gd[32];
                jubjub_hash(gd, (uint8_t *)&exp_sk->d, 11);

                error = ext_from_bytes(&gd_p, gd);
                if (!error) break;
            }

            // ivk
            // pk_d = gd_p * ivk
            // address = (d, pk_d)
            // bech32

            memmove(&exp_sk->out, &gd_p.u, 32);

            uint8_t ak[32];
            uint8_t nk[32];

            a_to_pk(ak, &exp_sk->ask);
            n_to_pk(nk, &exp_sk->nsk);
            calc_ivk((uint8_t *)&exp_sk->ivk, (uint8_t *)&ak, (uint8_t *)&nk);

            memmove(&exp_sk->out, &exp_sk->ivk, 32);

            // initialize diversifier_index = [0; 11]
            // loop:
            // map di to diversifier:
            // use FF1::<Aes256> with key = dk, radix = 2
            // encrypt di
            // check if di is valid:
            // group_hash = blake2s(di)
            // extended_point from gh bytes
            // check if valid point gd
            // return (di, d, gd)
            // increment di
            // end loop

            // ivk:
            // blake2s(ak|nk)
            // cast to Fr
            // pkd = gd * ivk
            
            // address: 11+32 bytes
            // bech32(d, pkd)
        }
        CATCH_OTHER(e) {
            error = e;
        }
        FINALLY {
        }
    }
    END_TRY;

    return error;
}

int calc_ivk(uint8_t *ivk, const uint8_t *ak, const uint8_t *nk) {
    blake2s_state hash_ctx;
    blake2s_param hash_params;
    memset(&hash_params, 0, sizeof(hash_params));
    hash_params.digest_length = 32;
    hash_params.fanout = 1;
    hash_params.depth = 1;
    memmove(&hash_params.personal, "Zcashivk", 8);

    blake2s_init_param(&hash_ctx, &hash_params);
    blake2s_update(&hash_ctx, ak, 32);
    blake2s_update(&hash_ctx, nk, 32);
    blake2s_final(&hash_ctx, ivk, 32);

    ivk[31] &= 0x07;

    return 0;
}
