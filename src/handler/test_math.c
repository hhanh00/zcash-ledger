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

#include "../globals.h"
#include "../types.h"
#include "../io.h"
#include "../sw.h"
#include "../common/buffer.h"
#include "../ui/display.h"
#include "../helper/send_response.h"
#include "../crypto/fr.h"
#include "../crypto/prf.h"
#include "../crypto/pallas.h"

uint8_t sak[32];

int handler_test_math() {
    int error = 0;
    fq_t d2;
    BEGIN_TRY {
        TRY {
            uint8_t hash[64];
            memset(hash, 1, 32);

            // SpendingKey => SpendAuthorizingKey
            prf_expand_seed(hash, 0x06); // hash to 512 bit value
            PRINTF("PRF EXPAND 6 %.*H\n", 64, hash);
            fv_from_wide(hash); // reduce to pallas scalar
            PRINTF("TO SCALAR %.*H\n", 32, hash);

            memmove(sak, hash, 32);
            PRINTF("SPENDING AUTHORIZATION KEY %.*H\n", 32, sak);

            jac_p_t p;
            hash_to_curve(&p, "z.cash:SinsemillaQ", 18, "z.cash:Orchard-MerkleCRH", 24);
            PRINTF("p.x %.*H\n", 32, p.x);
            PRINTF("p.y %.*H\n", 32, p.y);
            PRINTF("p.z %.*H\n", 32, p.z);
        }
        CATCH_OTHER(e) {
            error = e;
        }
        FINALLY {
        }
    }
    END_TRY;
    if (error != 0) return io_send_sw(error);
    return helper_send_response_bytes(d2, 32);
}
