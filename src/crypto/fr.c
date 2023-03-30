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
#include <lcx_math.h>

#include "fr.h"

#include "globals.h"

/// r = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7
static const uint8_t fr_m[32] = {
  0x0e, 0x7d, 0xb4, 0xea, 0x65, 0x33, 0xaf, 0xa9, 
  0x06, 0x67, 0x3b, 0x01, 0x01, 0x34, 0x3b, 0x00, 
  0xa6, 0x68, 0x20, 0x93, 0xcc, 0xc8, 0x10, 0x82, 
  0xd0, 0x97, 0x0e, 0x5e, 0xd6, 0xf7, 0x2c, 0xb7
};

void swap_endian(uint8_t *data, int8_t len) {
    for (int8_t i = 0; i < len / 2; i++) {
        uint8_t t = data[len - i - 1];
        data[len - i - 1] = data[i];
        data[i] = t;
    }
}

int fr_from_wide(uint8_t *data_512) {
    int error = 0;

    swap_endian(data_512, 64);
    error = cx_math_modm_no_throw(data_512, 64, fr_m, 32);
    memmove(data_512, data_512 + 32, 32);

    return error;
}
