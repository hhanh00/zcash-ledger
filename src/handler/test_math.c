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

#include "os.h"
#include "cx.h"

#include "get_fvk.h"
#include "../globals.h"
#include "../types.h"
#include "../io.h"
#include "../sw.h"
#include "../common/buffer.h"
#include "../ui/display.h"
#include "../helper/send_response.h"
#include "../crypto/key.h"
#include "../crypto/jubjub.h"

int handler_test_math() {
    explicit_bzero(&G_context, sizeof(G_context));
    expanded_spending_key_t response;
    int error = crypto_derive_spending_key(&response);
    if (error != 0) return io_send_sw(error);

    // fr_t p;
    // memset(&p, 0, 32);
    // p[31] = 12;
    // int error = jubjub_test(&p);
    // if (error != 0) return io_send_sw(error);

    // swap_endian((u_int8_t *)&p, 32);
    return helper_send_response_bytes((u_int8_t *)&G_context.address, 78);
}
