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
#include <string.h>  // memmove

#include "send_response.h"
#include "../constants.h"
#include "../globals.h"
#include "../sw.h"
#include "common/buffer.h"

int helper_send_response_fvk() {
    fvk_ctx_t fvk;
    memmove(&fvk.ak, &G_context.proofk_info.ak, 32);
    memmove(&fvk.nk, &G_context.proofk_info.nk, 32);
    memmove(&fvk.ovk, &G_context.exp_sk_info.ovk, 32);
    memmove(&fvk.dk, &G_context.exp_sk_info.dk, 32);
    return io_send_response(&(const buffer_t){.ptr = (uint8_t *)&fvk, .size = sizeof(fvk_ctx_t), .offset = 0}, SW_OK);
}

int helper_send_response_address() {
    return io_send_response(&(const buffer_t){.ptr = (uint8_t *)&G_context.address, .size = 78, .offset = 0}, SW_OK);
}

int helper_send_response_bytes(const u_int8_t *data, int data_len) {
    return io_send_response(&(const buffer_t){.ptr = data, .size = data_len, .offset = 0}, SW_OK);
}
