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
#include "../crypto/sinsemilla.h"
#include "../crypto/ff1.h"
#include "../crypto/f4jumble.h"
#include "../crypto/ua.h"
#include "../crypto/tx.h"
#include "../crypto/orchard.h"
#include "../crypto/key.h"

int handler_test_math() {
    int error = 0;
    BEGIN_TRY {
        TRY {
        }
        CATCH_OTHER(e) {
            error = e;
        }
        FINALLY {
        }
    }
    END_TRY;
    if (error != 0) return io_send_sw(error);
    return io_send_sw(SW_OK);
}
