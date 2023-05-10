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

#include "key.h"
#include "transparent.h"
#include "sapling.h"
#include "orchard.h"
#include "ua.h"
#include "../globals.h"

/// @brief Derive the master seed
/// @param tsk transparent secret key, seed of sapling and orchard keys
/// @param account 
/// @return 
int derive_tsk(uint8_t *tsk, uint8_t account) {
    uint32_t bip32_path[5] = {0x8000002C, 0x80000085, 0x80000000 | (uint32_t)account, 0, 0};
    os_perso_derive_node_bip32(CX_CURVE_256K1, bip32_path, 5,
        tsk, NULL);
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
}

void derive_default_keys() {
    if (!G_context.keys_derived)
        derive_keys_inner(0);
    encode_my_ua();
}

void derive_keys(uint8_t account) {
    if (!G_context.keys_derived || G_context.account != account)
        derive_keys_inner(account);
    encode_my_ua();
}
