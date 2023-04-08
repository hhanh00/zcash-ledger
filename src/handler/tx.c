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

#include <lcx_blake2.h>

#include "../globals.h"
#include "tx.h"
#include "../crypto/txid.h"
#include "../helper/send_response.h"

int init_tx() { return 0; }
int add_t_input_amount(uint64_t amount) { return 0; }
int add_t_output(t_out_t *output) { return 0; }
int add_s_output(s_out_t *output) { return 0; }
int set_sapling_net(int64_t balance) { return 0; }
int set_t_merkle_proof(t_proofs_t *t_proofs) { return 0; }
int set_s_merkle_proof(s_proofs_t *s_proofs) { return 0; }

