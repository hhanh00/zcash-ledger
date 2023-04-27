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

#include "debug.h"
#include "../helper/send_response.h"
#include "../globals.h"

uint8_t debug_buffer[500];
uint8_t *pdebug;

void init_debug() {
    pdebug = debug_buffer;
}

void append_debug(uint8_t *data, size_t data_len) {
    // No buffer overflow protection because it is debug
    memmove(pdebug, data, data_len);
    pdebug += data_len;
}

int get_debug_buffer(uint8_t i) {
    return helper_send_response_bytes(debug_buffer + i*250, 250);
}
