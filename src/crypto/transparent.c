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

#include "globals.h"
#include "address.h"

int derive_tsk(uint8_t *tsk, uint8_t account) {
    uint32_t bip32_path[5] = {0x8000002C, 0x80000085, 0x80000000 | (uint32_t)account, 0, 0};
    os_perso_derive_node_bip32(CX_CURVE_256K1, bip32_path, 5,
        tsk, NULL);
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

    memmove(G_context.transparent_key_info.pub_key, pk, 33);

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

int transparent_derive_pubkey(uint8_t account) {
    derive_pubkey(G_context.transparent_key_info.pub_key, account);
    derive_taddress(G_context.transparent_key_info.pkh, account);

    return 0;
}
