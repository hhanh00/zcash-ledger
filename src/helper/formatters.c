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

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t
#include <os.h>       // sprintf
#include <lcx_sha256.h>

#include "../globals.h"
#include "../crypto/address.h"
#include "../crypto/ua.h"
#include "../common/format.h"
#include "../common/base58.h"

void format_amount(uint64_t amount) {
    format_fpu64(G_store.amount, sizeof(G_store.amount), amount, 8);
}

void format_t_address(uint8_t *address_hash) {
    to_t_address(G_store.address, address_hash);
}

void format_s_address(uint8_t *address) {
    to_address_bech32(G_store.address, address, address + 11);
}

void format_u_address(uint8_t *address) {
    encode_ua(address);
}
