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
#include <lcx_blake2.h>

#include "prf.h"

#include "globals.h"

void prf_expand_seed(uint8_t *key, uint8_t t) {
    cx_blake2b_t hash_ctx;

    cx_blake2b_init2_no_throw(&hash_ctx, 512, NULL, 0, (uint8_t *)"Zcash_ExpandSeed", 16);
    cx_hash((cx_hash_t *)&hash_ctx, 0, key, 32, NULL, 0);
    cx_hash((cx_hash_t *)&hash_ctx, CX_LAST, &t, 1, key, 64);
}

