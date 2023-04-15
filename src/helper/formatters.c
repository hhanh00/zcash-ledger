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

#include "../globals.h"
#include "../crypto/key.h"
#include "../common/format.h"

void format_amount(uint8_t *amount) {
    uint64_t value;
    memmove(&value, amount, sizeof(uint64_t)); // need to copy because of memory alignment 
    format_fpu64(G_context.amount, sizeof(G_context.amount), value, 8);
}

void format_s_address(uint8_t *address) {
    to_address_bech32(G_context.address, address, address + 11);
}
