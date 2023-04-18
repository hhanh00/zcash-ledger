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

#include "key.h"
#include "prf.h"
#include "fr.h"
#include "ff1.h"
#include "jubjub.h"
#include "blake2s.h"
#include "bech32.h"

#include "globals.h"
#include "../common/base58.h"
#include "../ui/display.h"
#include "../ui/menu.h"
#include "../helper/send_response.h"

int derive_tsk(uint8_t *tsk, uint8_t account) {
    uint32_t bip32_path[5] = {0x8000002C, 0x80000085, 0x80000000 | (uint32_t)account, 0, 0};
    os_perso_derive_node_bip32(CX_CURVE_256K1, bip32_path, 5,
        tsk, NULL);
    return 0;
}

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

int derive_pubkey(uint8_t *pk, uint8_t account) {
    uint8_t tsk[32];
    cx_ecfp_private_key_t t_prvk;
    cx_ecfp_public_key_t t_pubk;
    derive_tsk(tsk, account);
    cx_ecfp_init_private_key_no_throw(CX_CURVE_SECP256K1, tsk, 32, &t_prvk);
    cx_ecfp_generate_pair(CX_CURVE_SECP256K1, &t_pubk, &t_prvk, 1);
    PRINTF("PK: %.*H\n", 65, t_pubk.W);

    memmove(pk + 1, t_pubk.W + 1, 32); // X
    pk[0] = ((t_pubk.W[64] & 1) == 0) ? 0x02 : 0x03; // parity of Y
    PRINTF("CPK: %.*H\n", 33, pk);

    return 0;
}

int derive_taddress(uint8_t *pkh, uint8_t account) {
    uint8_t pk[33];
    derive_pubkey(pk, account);
    
    cx_sha256_t sha_hasher;
    cx_sha256_init_no_throw(&sha_hasher);
    cx_hash_no_throw((cx_hash_t *)&sha_hasher, CX_LAST, pk, 33, pk, 32);
    PRINTF("SHA256: %.*H\n", 32, pk);

    cx_ripemd160_t ripemd_hasher;
    cx_ripemd160_init_no_throw(&ripemd_hasher);
    cx_hash_no_throw((cx_hash_t *)&ripemd_hasher, CX_LAST, pk, 32, pkh, 20);
    PRINTF("PKH: %.*H\n", 20, pkh);

    return 0;
}

/**
 * 
*/
void crypto_derive_spending_key(int8_t account) {
    expanded_spending_key_t *exp_sk = &G_context.exp_sk_info;
    uint8_t spending_key[32];

    ui_display_processing();
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
    calc_ivk(ivk, ak, nk);

    extended_point_t pk_d;
    swap_endian(ivk, 32);
    ext_base_mult(&pk_d, &g_d, &ivk);

    uint8_t pk_d_bytes[32];
    ext_to_bytes(pk_d_bytes, &pk_d);

    to_address_bech32(G_context.address, exp_sk->d, pk_d_bytes);
    ui_menu_main();
}

void calc_ivk(uint8_t *ivk, const uint8_t *ak, const uint8_t *nk) {
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

void to_address_bech32(char *address, uint8_t *d, uint8_t *pk_d) {
    uint8_t buffer[70];
    uint8_t data[43];
    memmove(data, d, 11);
    memmove(data + 11, pk_d, 32);
    size_t buffer_len = 0;
    convert_bits(buffer, &buffer_len, 5, data, 43, 8, 1);
    bech32_encode(address, "zs", buffer, buffer_len, BECH32_ENCODING_BECH32);
}

uint8_t address[26];
uint8_t hash[32];
cx_sha256_t sha_hasher;

/**
 * out_address must has length 80 bytes at least
*/
void to_t_address(char *out_address, uint8_t *kh) { 
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

int get_proofgen_key() {
    proofgen_key_t proof_gen_key;
    memmove(proof_gen_key.ak, G_context.proofk_info.ak, 32);
    memmove(proof_gen_key.nsk, G_context.exp_sk_info.nsk, 32);
    swap_endian(proof_gen_key.nsk, 32);
    return helper_send_response_bytes((uint8_t *)&proof_gen_key, 64);
}
