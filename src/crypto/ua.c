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
#include "bech32.h"
#include "f4jumble.h"
#include "../helper/send_response.h"
#include "../ui/display.h"
#include "../globals.h"

void encode_ua_inner(uint8_t *p, uint8_t *receivers);

int encode_my_ua() {
    memset(G_store.receivers, 0, UA_LEN);
    uint8_t *p = G_store.receivers;
    *p++ = 0;
    *p++ = 20;
    memmove(p, G_context.transparent_key_info.pkh, 20); p += 20;
    *p++ = 2;
    *p++ = 43;
    memmove(p, G_context.exp_sk_info.d, 11); p += 11;
    memmove(p, G_context.exp_sk_info.pk_d, 32); p += 32;
    #ifdef ORCHARD
    *p++ = 3;
    *p++ = 43;
    memmove(p, G_context.orchard_key_info.address, 43); p += 43;
    #endif

    encode_ua_inner(p, G_store.receivers);

    return 0;
}

int encode_ua(uint8_t *orchard_address) {
    memset(G_store.receivers, 0, UA_LEN);
    uint8_t *p = G_store.receivers;
    *p++ = 3;
    *p++ = 43;
    memmove(p, orchard_address, 43); p += 43;

    encode_ua_inner(p, G_store.receivers);
    return 0;
}

void encode_ua_inner(uint8_t *p, uint8_t *receivers) {
    *p++ = 'u';
    p += 15;
    size_t receivers_len = p - receivers;
    // PRINTF("padded %.*H\n", receivers_len, receivers);

    f4jumble(receivers, receivers_len);
    size_t buffer_len = 0;
    // PRINTF("receivers %.*H\n", receivers_len, receivers);
    convert_bits(G_store.bech32_buffer, &buffer_len, 5, receivers, receivers_len, 8, 1);
    bech32_encode(G_store.address, "u", G_store.bech32_buffer, buffer_len, BECH32_ENCODING_BECH32M);
    PRINTF("ua %s\n", G_store.address);
}
