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
#include <ox_bn.h>
#include <blake2s.h>

#include "fr.h"
#include "pallas.h"

#include "globals.h"

void orchard_derive_spending_key(int8_t account) {
    /*
    keys:
    - derive spending key from bip32 
    - prf expand to ask
    - prf expand to nk
    - prf expand to nivk
    - ak = G * ask
    - negate ask if ak_y is odd
    - ak = extract(ak)
    - ivk = hash_nivk(ak|nk)
    - R = prf expand of ak|nk
    - R = dk|ovk
    
    address:
    - di = 0
    - d = prp_dk(di)
    - G_d = group_hash(d)
    - pk_d = KA(G_d * ivk)
    - address = (d, pk_d)

    differences vs sapling
    - prf expand = blake2b hash 64 bytes, perso Zcash_ExpandSeed
        sk | t
        Note: same as sapling
    - ECC is on pallas instead of jubjub
    - point representation does not need to encode the parity of  y
    because we force it to be even by negating the secret key
    - to_bytes, from_bytes: same as jubjub with different ff
    - extract(p) = p_x
    - group_hash = TBD

    */

}
