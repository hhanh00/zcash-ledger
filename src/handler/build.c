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
#include "../globals.h"
#include "../helper/send_response.h"
#include "build.h"
#include "../crypto/key.h"

int handler_build(uint8_t account) {
    if (account != G_context.account) {
        G_context.account = account;
        explicit_bzero(&G_context, sizeof(G_context));
        int error = 0;

        BEGIN_TRY {
            TRY {
                crypto_derive_spending_key(account);
            }
            CATCH_OTHER(e) {
                error = e;
            }
            FINALLY {
            }
        }
        END_TRY;

        if (error != 0) return io_send_sw(error);
    }
    return helper_send_response_bytes(NULL, 0);
}
