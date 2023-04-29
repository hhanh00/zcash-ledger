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

#include "sapling.h"
#include "prf.h"
#include "fr.h"
#include "ff1.h"
#include "jubjub.h"
#include "blake2s.h"

#include "globals.h"
#include "address.h"
#include "../ui/display.h"
#include "../ui/menu.h"
#include "../helper/send_response.h"

int derive_ssk(uint8_t *ssk, uint8_t account) {
    uint32_t bip32_path[5] = {0x8000002C, 0x80000085, 0x80000000 | (uint32_t)account, 0, 0};
    os_perso_derive_node_bip32(CX_CURVE_256K1,
                                bip32_path,
                                5,
                                ssk,
                                NULL);

    cx_blake2b_init2_no_throw(&G_context.signing_ctx.hasher, 256,
                              NULL, 0,
                              (uint8_t *) "ZMSeedPRNG__Hash", 16);
    cx_hash((cx_hash_t *) &G_context.signing_ctx.hasher,
            CX_LAST,
            ssk, 32,
            ssk, 32);
    return 0;
}

/**
 * 
*/
void sapling_derive_spending_key(int8_t account) {
    expanded_spending_key_t *exp_sk = &G_context.exp_sk_info;
    uint8_t spending_key[32];

    ui_display_processing("z-key");
    derive_ssk(spending_key, account);
    G_context.account = account;

    uint8_t xsk[64];
    memmove(xsk, spending_key, 32); // ask
    prf_expand_seed(xsk, 0);
    fr_from_wide(xsk);
    memmove(exp_sk->ask, xsk, 32);

    memmove(xsk, spending_key, 32); // nsk
    prf_expand_seed(xsk, 1);
    fr_from_wide(xsk);
    memmove(exp_sk->nsk, xsk, 32);

    memmove(xsk, spending_key, 32); // ovk
    prf_expand_seed(xsk, 2);
    memmove(exp_sk->ovk, xsk, 32);

    // dk - diversifier key
    memmove(xsk, spending_key, 32); // ovk
    prf_expand_seed(xsk, 0x10);
    memmove(exp_sk->dk, xsk, 32);

    uint8_t di[11];
    memset(di, 0, 11);

    extended_niels_point_t g_d;
    for (uint32_t i = 0; ; i++) {
        PRINTF("i %d\n", i);
        memset(di, 0, 11);
        memmove(di, &i, 4);

        ff1(exp_sk->d, exp_sk->dk, di);

        uint8_t gd_hash[32];
        jubjub_hash(gd_hash, exp_sk->d, 11);

        int error = extn_from_bytes(&g_d, gd_hash);
        // if error, retry with next di
        if (!error) break;
    }

    uint8_t ak[32];
    uint8_t nk[32];

    a_to_pk(ak, &exp_sk->ask);
    memmove(G_context.proofk_info.ak, ak, 32);

    n_to_pk(nk, &exp_sk->nsk);
    memmove(G_context.proofk_info.nk, nk, 32);

    fr_t ivk;
    sapling_ivk(ivk, ak, nk);

    extended_point_t pk_d;
    swap_endian(ivk, 32);
    ext_base_mult(&pk_d, &g_d, &ivk);

    ext_to_bytes(exp_sk->pk_d, &pk_d);

    to_address_bech32(G_context.address, exp_sk->d, exp_sk->pk_d);
    ui_menu_main();
}

void sapling_ivk(uint8_t *ivk, const uint8_t *ak, const uint8_t *nk) {
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
}

int get_proofgen_key() {
    proofgen_key_t proof_gen_key;
    memmove(proof_gen_key.ak, G_context.proofk_info.ak, 32);
    memmove(proof_gen_key.nsk, G_context.exp_sk_info.nsk, 32);
    swap_endian(proof_gen_key.nsk, 32);
    return helper_send_response_bytes((uint8_t *)&proof_gen_key, 64);
}
