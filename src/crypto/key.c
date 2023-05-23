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

#include "address.h"
#include "key.h"
#include "transparent.h"
#include "sapling.h"
#include "../globals.h"

#ifdef USE_TEST_KEY
// Speculos test key
// I HIGHLY recommend that you use your OWN seed phrase with Speculos, NOT this one
// There is a bot that will drain any funds sent to the transparent address
static const uint8_t TEST_KEY[] = {
    0xA6, 0x1C, 0x4B, 0xA2, 0xCD, 0x68, 0xC2, 0xE9, 0x50, 0x17, 0xE6, 0xD9, 0x02, 0x11, 0x5C, 0x04, 0x9F, 0xBE, 0x16, 0xF7, 0xC8, 0xD4, 0xC1, 0xF4, 0x68, 0x0C, 0x4F, 0x6E, 0xC8, 0xFC, 0xCD, 0xBF
};
#endif

void encode_sapling() {
    to_address_bech32(G_store.address, G_context.exp_sk_info.d, G_context.exp_sk_info.pk_d);
}

/// @brief Derive the master seed
/// @param tsk transparent secret key, seed of sapling and orchard keys
/// @param account 
/// @return 
int derive_tsk(uint8_t *tsk, uint8_t account) {
    uint32_t bip32_path[5] = {0x8000002C, 0x80000085, 0x80000000 | (uint32_t)account, 0, 0};
    os_perso_derive_node_bip32(CX_CURVE_256K1, bip32_path, 5,
        tsk, NULL);

    #ifdef USE_TEST_KEY
    memmove(tsk, TEST_KEY, 32);
    #endif

    PRINTF("TOP level key %.*H\n", 32, tsk);
    return 0;
}

static void derive_keys_inner(uint8_t account) {
    transparent_derive_pubkey(account);
    sapling_derive_spending_key(account);
    #ifdef ORCHARD
    orchard_derive_spending_key(account);
    #endif
    G_context.account = account;
    G_context.keys_derived = true;
    check_canary();
}

void derive_default_keys() {
    if (!G_context.keys_derived)
        derive_keys_inner(0);
    encode_sapling();
}

void derive_keys(uint8_t account) {
    if (!G_context.keys_derived || G_context.account != account)
        derive_keys_inner(account);
    encode_sapling();
}
