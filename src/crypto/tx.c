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
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // memset, explicit_bzero

#include <ox_bn.h>
#include <lcx_blake2.h>
#include <lcx_ecdsa.h>
#include "sw.h"

#include "../globals.h"
#include "fr.h"
#include "key.h"
#include "transparent.h"
#include "sapling.h"
#include "tx.h"
#include "../ui/display.h"
#include "../ui/menu.h"
#include "../helper/send_response.h"
#include "../ui/action/validate.h"

int sign_transparent(uint8_t *sighash) {
    ui_display_processing("sign t");
    derive_tsk(G_store.tsk, G_context.account);

    transparent_ecdsa(G_store.signature, G_store.tsk, sighash);

    ui_menu_main();
    return helper_send_response_bytes(G_store.signature, 64);
}

int sign_sapling(uint8_t *sighash, uint8_t *alpha) {
    ui_display_processing("sign z");

    sapling_sign(G_store.signature, sighash, alpha);

    PRINTF("signature %.*H\n", 64, G_store.signature);

    ui_menu_main();
    return helper_send_response_bytes(G_store.signature, 64);
}
