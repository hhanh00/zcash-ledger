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
#include "sinsemilla.h"
#include "prf.h"
#include "ff1.h"

#include "globals.h"

static uint8_t spending_key[32];
void orchard_derive_spending_key(int8_t account) {
    uint8_t hash[64];
    uint32_t bip32_path[5] = {0x8000002C, 0x80000085, 0x80000000 | (uint32_t)account, 0, 0};
    os_perso_derive_node_bip32(CX_CURVE_256K1,
                                bip32_path,
                                5,
                                spending_key,
                                NULL);

    PRINTF("SPENDING KEY %.*H\n", 32, spending_key);
    memmove(hash, spending_key, 32);

    // SpendingKey => SpendAuthorizingKey
    prf_expand_seed(hash, 0x06); // hash to 512 bit value
    PRINTF("PRF EXPAND 6 %.*H\n", 64, hash);
    fv_from_wide(hash); // reduce to pallas scalar
    PRINTF("TO SCALAR %.*H\n", 32, hash);
    memmove(G_context.orchard_key_info.ask, hash, 32);
    PRINTF("SPENDING AUTHORIZATION KEY %.*H\n", 32, G_context.orchard_key_info.ask);

    jac_p_t p;
    pallas_base_mult(&p, &SPEND_AUTH_GEN, &G_context.orchard_key_info.ask);
    pallas_to_bytes(G_context.orchard_key_info.ak, &p);
    if ((G_context.orchard_key_info.ak[31] & 0x7F) != 0) {
        fv_negate(&G_context.orchard_key_info.ask);
        pallas_base_mult(&p, &SPEND_AUTH_GEN, &G_context.orchard_key_info.ask);
        pallas_to_bytes(G_context.orchard_key_info.ak, &p);
    }

    memmove(hash, spending_key, 32);
    prf_expand_seed(hash, 0x07); // hash to 512 bit value
    PRINTF("PRF EXPAND 7 %.*H\n", 64, hash);
    fp_from_wide(hash); // reduce to pallas base
    PRINTF("TO BASE %.*H\n", 32, hash);
    memmove(G_context.orchard_key_info.nk, hash, 32);
    PRINTF("NULLIFIER DERIVATION KEY %.*H\n", 32, G_context.orchard_key_info.nk);

    memmove(hash, spending_key, 32);
    prf_expand_seed(hash, 0x08); // hash to 512 bit value
    PRINTF("PRF EXPAND 8 %.*H\n", 64, hash);
    fv_from_wide(hash); // reduce to pallas scalar
    PRINTF("TO SCALAR %.*H\n", 32, hash);
    memmove(G_context.orchard_key_info.rivk, hash, 32);
    PRINTF("RIVK %.*H\n", 32, G_context.orchard_key_info.rivk);

    memmove(hash, G_context.orchard_key_info.rivk, 32); 
    swap_endian(hash, 32); // to_repr
    uint8_t dst = 0x82;
    cx_blake2b_t hash_ctx;
    cx_blake2b_init2_no_throw(&hash_ctx, 512, NULL, 0, (uint8_t *)"Zcash_ExpandSeed", 16);
    PRINTF("rivk %.*H\n", 32, hash);
    cx_hash((cx_hash_t *)&hash_ctx, 0, hash, 32, NULL, 0);
    PRINTF("dst %.*H\n", 1, &dst);
    cx_hash((cx_hash_t *)&hash_ctx, 0, &dst, 1, NULL, 0);
    PRINTF("ak %.*H\n", 32, G_context.orchard_key_info.ak);
    cx_hash((cx_hash_t *)&hash_ctx, 0, G_context.orchard_key_info.ak, 32, NULL, 0);
    memmove(hash, G_context.orchard_key_info.nk, 32); 
    swap_endian(hash, 32); // to_repr
    PRINTF("nk %.*H\n", 32, hash);
    cx_hash((cx_hash_t *)&hash_ctx, 0, hash, 32, NULL, 0);
    cx_hash((cx_hash_t *)&hash_ctx, CX_LAST, NULL, 0, hash, 64);
    PRINTF("dk %.*H\n", 32, hash);
    PRINTF("ovk %.*H\n", 32, hash + 32);

    memmove(G_context.orchard_key_info.dk, hash, 32);

    sinsemilla_state_t sinsemilla;
    init_commit(&sinsemilla, (uint8_t *)"z.cash:Orchard-CommitIvk-M", 26);
    memmove(hash, G_context.orchard_key_info.nk, 32); 
    swap_endian(hash, 32); // to_repr
    hash_sinsemilla(&sinsemilla, G_context.orchard_key_info.ak, 255);
    hash_sinsemilla(&sinsemilla, hash, 255);
    finalize_commit(&sinsemilla, (uint8_t *)"z.cash:Orchard-CommitIvk-r", 26, 
        &G_context.orchard_key_info.rivk, hash);

    PRINTF("commit %.*H\n", 32, hash);
    memmove(G_context.orchard_key_info.ivk, hash, 32);

    // ivk is fp_t but can be safely cast to fv_t
    // because the modulus of vesta is smaller than pasta

    uint8_t d[11];
    memset(d, 0, 11);
    ff1(d, G_context.orchard_key_info.dk, d);
    PRINTF("d %.*H\n", 11, d);
    memcpy(G_context.orchard_key_info.div, d, 11);

    jac_p_t G_d;
    hash_to_curve(&G_d, (uint8_t *)"z.cash:Orchard-gd", 17,
        d, 11);

    pallas_base_mult(&G_d, &G_d, (fv_t *)&G_context.orchard_key_info.ivk);
    pallas_to_bytes(hash, &G_d);
    PRINTF("pk_d %.*H\n", 32, hash);
    memmove(G_context.orchard_key_info.pk_d, hash, 32);

    memmove(G_context.orchard_key_info.address, G_context.orchard_key_info.div, 11);
    memmove(G_context.orchard_key_info.address + 11, G_context.orchard_key_info.pk_d, 32);
    PRINTF("address %.*H\n", 43, G_context.orchard_key_info.address);
}

int cmx(uint8_t *address, uint64_t value, uint8_t *rseed, uint8_t *rho) {
    uint8_t hash[64];
    uint8_t g_d[32];
    uint8_t esk[32];
    uint8_t psi[32];
    fv_t rcm;

    memmove(hash, rseed, 32);
    prf_expand_seed_with_ad(hash, 4, rho, 32);
    PRINTF("PRF ESK %.*H\n", 64, hash);
    fv_from_wide(hash);
    memmove(esk, hash, 32);
    PRINTF("SCALAR ESK %.*H\n", 32, esk);

    memmove(hash, rseed, 32);
    prf_expand_seed_with_ad(hash, 9, rho, 32);
    PRINTF("PRF PSI %.*H\n", 64, hash);
    fp_from_wide(hash);
    memmove(psi, hash, 32);
    PRINTF("BASE PSI %.*H\n", 32, psi);

    memmove(hash, rseed, 32);
    prf_expand_seed_with_ad(hash, 5, rho, 32);
    PRINTF("PRF RCM %.*H\n", 64, hash);
    fv_from_wide(hash);
    memmove(rcm, hash, 32);
    PRINTF("SCALAR RCM %.*H\n", 32, rcm);

    jac_p_t G_d;
    hash_to_curve(&G_d, (uint8_t *)"z.cash:Orchard-gd", 17,
        address, 11);
    pallas_to_bytes(g_d, &G_d);
    PRINTF("G_d %.*H\n", 32, g_d);

    sinsemilla_state_t sinsemilla;

    init_commit(&sinsemilla, (uint8_t *)"z.cash:Orchard-NoteCommit-M", 27);
    hash_sinsemilla(&sinsemilla, g_d, 256);
    hash_sinsemilla(&sinsemilla, address + 11, 256);
    hash_sinsemilla(&sinsemilla, (uint8_t *)&value, 64);
    hash_sinsemilla(&sinsemilla, rho, 255);
    memmove(hash, psi, 32); // psi.to_repr
    swap_endian(hash, 32);
    hash_sinsemilla(&sinsemilla, hash, 255);
    finalize_commit(&sinsemilla, (uint8_t *)"z.cash:Orchard-NoteCommit-r", 27, &rcm, hash);

    PRINTF("CMX %.*H\n", 32, hash);

    return 0;
}
