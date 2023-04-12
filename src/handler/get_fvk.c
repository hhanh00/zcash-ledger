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
#include <string.h>  // memmove

#include "os.h"

#include "get_fvk.h"
#include "../helper/send_response.h"
#include "globals.h"

int handler_get_fvk() {
    fvk_ctx_t fvk;
    memmove(&fvk.ak, &G_context.proofk_info.ak, 32);
    memmove(&fvk.nk, &G_context.proofk_info.nk, 32);
    memmove(&fvk.ovk, &G_context.exp_sk_info.ovk, 32);
    memmove(&fvk.dk, &G_context.exp_sk_info.dk, 32);
    return helper_send_response_bytes((uint8_t *)&fvk, sizeof(fvk_ctx_t));
}
