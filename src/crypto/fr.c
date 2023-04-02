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

#include "fr.h"

#include "globals.h"

void swap_endian(uint8_t *data, int8_t len) {
    for (int8_t i = 0; i < len / 2; i++) {
        uint8_t t = data[len - i - 1];
        data[len - i - 1] = data[i];
        data[i] = t;
    }
}

void swap_bit_endian(uint8_t *data, int8_t len) {
    for (int i = 0; i < len; i++) {
        uint8_t b = data[i];
        b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
        b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
        b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
        data[i] = b;
    }
}

void fr_from_wide(uint8_t *data_512) {
    swap_endian(data_512, 64);
    cx_math_modm_no_throw(data_512, 64, fr_m, 32);
    // Once we do the mod operation, the 32 most significant bytes are 0
    // because the modulus is < 2^256
    // pick the lower part
    memmove(data_512, data_512 + 32, 32);
}

