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

#include <ox_bn.h>
#include <lcx_blake2.h>
#include <lcx_ecdsa.h>
#include "sw.h"

#include "../globals.h"
#include "fr.h"
#include "key.h"
#include "transparent.h"
#include "sapling.h"
#include "tx.h"
#include "../ui/display.h"
#include "../ui/menu.h"
#include "../helper/send_response.h"
#include "../ui/action/validate.h"

// Zcash___TxInHash when there is no t-inputs
const uint8_t sapling_tx_in_hash[] = {
    0x3e, 0xac, 0xa6, 0xf7, 0x04, 0x79, 0xf3, 0xed, 
    0x3d, 0xb1, 0x1a, 0x00, 0x17, 0x07, 0xef, 0x9d, 
    0x8f, 0x0f, 0x66, 0x1c, 0xd4, 0x53, 0x42, 0x47, 
    0x32, 0x03, 0xc8, 0x6b, 0xa1, 0xff, 0x89, 0x75
};

cx_chacha_context_t chacha_rseed_rng;
cx_chacha_context_t chacha_alpha_rng;

static int transparent_bundle_hash();
static int sapling_bundle_hash();
static int orchard_bundle_hash();
static int finish_sighash(uint8_t *sighash, const uint8_t *txin_sig_digest);

int init_tx() {
    memset(&G_context.signing_ctx, 0, sizeof(tx_signing_ctx_t));
    G_context.signing_ctx.stage = T_IN;
    uint8_t mseed[32];
    // get 32 random bytes to seed our alpha & rseed PRNG
    cx_get_random_bytes(mseed, 32);

    uint8_t seed_rng[32];
    cx_blake2b_init2_no_throw(&G_context.hasher, 256,
                              NULL, 0,
                              (uint8_t *) "ZRSeedPRNG__Hash", 16);
    cx_hash((cx_hash_t *) &G_context.hasher,
            CX_LAST,
            mseed, 32,
            seed_rng, 32);

    cx_chacha_init(&chacha_rseed_rng, 20);
    cx_chacha_set_key(&chacha_rseed_rng, seed_rng, 32);

    cx_blake2b_init2_no_throw(&G_context.hasher, 256,
                              NULL, 0,
                              (uint8_t *) "ZAlphaPRNG__Hash", 16);
    cx_hash((cx_hash_t *) &G_context.hasher,
            CX_LAST,
            mseed, 32,
            seed_rng, 32);

    cx_chacha_init(&chacha_alpha_rng, 20);
    cx_chacha_set_key(&chacha_alpha_rng, seed_rng, 32);

    cx_blake2b_init2_no_throw(&G_context.hasher,
                              256,
                              NULL,
                              0,
                              (uint8_t *) "ZTxTrAmountsHash",
                              16);

    return helper_send_response_bytes(mseed, 32);
}

int change_stage(uint8_t new_stage) {
    if (new_stage != G_context.signing_ctx.stage + 1) {
        reset_app();
        return io_send_sw(SW_BAD_STATE);
    }

    cx_hash_t *ph = (cx_hash_t *)&G_context.hasher;

    switch (new_stage) {
        case T_OUT:
            cx_hash(ph, CX_LAST,
                    NULL, 0,
                    G_context.signing_ctx.amount_hash, 32);
            PRINTF("T AMOUNTS: %.*H\n", 32, G_context.signing_ctx.amount_hash);
            cx_blake2b_init2_no_throw(&G_context.hasher, 256,
                                      NULL, 0,
                                      (uint8_t *) "ZTxIdOutputsHash", 16);
            break;
        case S_OUT:
            cx_hash(ph, CX_LAST,
                    NULL, 0,
                    G_context.signing_ctx.t_outputs_hash, 32);
            PRINTF("T OUTPUTS: %.*H\n", 32, G_context.signing_ctx.t_outputs_hash);
            cx_blake2b_init2_no_throw(&G_context.hasher,
                                      256,
                                      NULL,
                                      0,
                                      (uint8_t *) "ZTxIdSOutC__Hash",
                                      16);
            break;
        case FEE:
            #ifdef ORCHARD
            cx_hash(ph, CX_LAST,
                    NULL, 0,
                    G_context.signing_ctx.o_compact_hash, 32);
            PRINTF("O ACTIONS COMPACT: %.*H\n", 32, G_context.signing_ctx.o_compact_hash);
            #endif

            // Transaction in/out must have been confirmed
            // We can compute the sig hash components

            break;
        default: // should have been caught by the check at the top
            return io_send_sw(SW_INVALID_PARAM);
    }
    G_context.signing_ctx.stage = new_stage;

    return io_send_sw(SW_OK);
}

const uint8_t PAY2PKH_1[] = { 0x19, 0x76, 0xA9, 0x14 }; // First part of the pay2pkh bitcoin script
const uint8_t PAY2PKH_2[] = { 0x88, 0xAC };             // Second part of the pay2pkh bitcoin script

int add_t_input_amount(uint64_t amount) {
    if (G_context.signing_ctx.stage != T_IN) {
        reset_app();
        return io_send_sw(SW_BAD_STATE);
    }

    // In the T_IN stage, we receive transparent input amounts
    // The hasher must be setup for ZTxTrAmountsHash
    // This is prepared in the init_tx function
    // The next stage is T_OUT

    G_context.signing_ctx.has_t_in = true;
    G_context.signing_ctx.t_net += (int64_t)amount;
    CHECK_MONEY(G_context.signing_ctx.t_net);
    cx_hash((cx_hash_t *) &G_context.hasher, 0, (uint8_t *) &amount, 8, NULL, 0);

    return io_send_sw(SW_OK);
}

int add_t_output(t_out_t *output, bool confirmation) {
    if (G_context.signing_ctx.stage != T_OUT) {
        reset_app();
        return io_send_sw(SW_BAD_STATE);
    }
    if (output->address_type != 0)  // only p2pkh for now
        return SW_INVALID_PARAM;

    if (memcmp(output->address_hash, G_context.transparent_key_info.pkh, 20) == 0)
        confirmation = false;

    // In the T_OUT stage, we receive transparent outputs
    // We computed the ZTxTrAmountsHash and prepared the hasher
    // for ZTxIdOutputsHash in the change_stage function
    // The next stage is S_OUT

    G_context.signing_ctx.has_t_out = true;
    G_context.signing_ctx.t_net -= (int64_t)output->amount;

    cx_hash_t *ph = (cx_hash_t *) &G_context.hasher;
    cx_hash(ph, 0, (uint8_t *) &output->amount, 8, NULL, 0);  // output amount
    cx_hash(ph, 0, PAY2PKH_1, 4, NULL, 0);       // <size> OP_DUP OP_HASH160 <key size>
    cx_hash(ph, 0, output->address_hash, 20, NULL, 0);  // pk hash
    cx_hash(ph, 0, PAY2PKH_2, 2, NULL, 0);              // OP_EQUALVERIFY OP_CHECKSIG

    if (confirmation)
        return ui_confirm_t_out(output);
    return io_send_sw(SW_OK);
}

extern uint8_t debug[250];

int add_s_output(s_out_t *output, bool confirmation) {
    if (G_context.signing_ctx.stage != S_OUT) {
        reset_app();
        return io_send_sw(SW_BAD_STATE);
    }
    ui_display_processing("z-out");

    // In the S_OUT stage, we receive sapling outputs
    // We computed the ZTxIdOutputsHash and move on to
    // ZTxIdSOutC__Hash, the compact sapling outputs hash
    // The next stage is O_ACTION

    G_context.signing_ctx.has_s_out = true;
    G_context.signing_ctx.amount_s_out += output->amount;

    if ((memcmp(output->address, G_context.exp_sk_info.d, 11) == 0 &&
        memcmp(output->address + 11, G_context.exp_sk_info.pk_d, 32) == 0)
        || output->amount == 0)
        confirmation = false;

    uint8_t cmu[32];
    PRINTF("ADDRESS: %.*H\n", 43, output->address);
    PRINTF("RSEED: %.*H\n", 32, output->rseed);
    PRINTF("AMOUNT: %.*H\n", 8, &output->amount);

    get_cmu(cmu, output->address, output->address + 11, output->amount, output->rseed);
    PRINTF("CMU %.*H\n", 32, cmu);

    cx_hash_t *ph = (cx_hash_t *) &G_context.hasher;
    cx_hash(ph, 0, cmu, 32, NULL, 0);           // cmu
    cx_hash(ph, 0, output->epk, 32, NULL, 0);  // ephemeral key
    cx_hash(ph, 0, output->enc, 52, NULL, 0);  // first 52 bytes of encrypted note

    PRINTF("CONFIRMATION %d\n", confirmation);
    PRINTF("AMOUNT: %.*H\n", 8, &output->amount);
    memmove(G_store.out_buffer, cmu, 32);
    if (confirmation)
        return ui_confirm_s_out(output);
    ui_menu_main();
    if (G_context.signing_ctx.flags)
        return helper_send_response_bytes(cmu, 32);
    return io_send_sw(SW_OK);
}

int set_s_net(int64_t balance) {
    G_context.signing_ctx.has_s_in = balance != (int64_t)G_context.signing_ctx.amount_s_out;
    G_context.signing_ctx.s_net = balance;

    return io_send_sw(SW_OK);
}

int confirm_fee(bool confirmation) {
    if (G_context.signing_ctx.stage != FEE) {
        reset_app();
        return io_send_sw(SW_BAD_STATE);
    }

    int64_t fee = G_context.signing_ctx.t_net + G_context.signing_ctx.s_net;
    transparent_bundle_hash();
    sapling_bundle_hash();
    
    // Compute the shielded sighash
    // when there is no t_in, do not include the tx_in_hash at all
    // This is going to be used by every shielded signature, therefore we cache the result
    finish_sighash(G_context.signing_ctx.sapling_sig_hash, 
        G_context.signing_ctx.has_t_in ? sapling_tx_in_hash : NULL);

    if (confirmation)
        return ui_confirm_fee(fee);
    else 
        G_context.signing_ctx.stage = SIGN;

    if (G_context.signing_ctx.flags)
        return get_shielded_hashes();
    return io_send_sw(SW_OK);
}

int transparent_bundle_hash() {
    /*
    The transparent bundle is different than the shielded bundles
    - If there are no transparent inputs and no transparent outputs, the bundle is a hash of an empty []
    - If there outputs but no inputs, we only hash prevouts, sequences and outputs
    - If there are inputs, we need to hash: hash_type, prevouts, amounts, script_pubkeys, sequences, outputs
        and a txin_sig. The txin_sig depends on the input with sign, i.e. every transparent input signs a different
        sig_hash. To reduce hashing, we save the "midstate" of the hasher just before the txin_sig part
        and resume the hashing with txin_sig.
        When signing a shielded spent/action, we use a constant txin_sig = sapling_tx_in_hash
        Notice every shielded signature is computed on the same sig_hash
    */

    // cx_hash_t *ph = (cx_hash_t *)&G_context.signing_ctx.transparent_hasher;
    // cx_blake2b_init2_no_throw(&G_context.signing_ctx.transparent_hasher, 256,
    //                         NULL, 0,
    //                         (uint8_t *) "ZTxIdTranspaHash", 16);
    // if (G_context.signing_ctx.has_t_in || G_context.signing_ctx.has_t_out) {
    //     // Without t-in, the sighash is the same as the txid
    //     if (G_context.signing_ctx.has_t_in) {
    //         uint8_t hash_type = 1;
    //         cx_hash(ph, 0, &hash_type, 1, NULL, 0);
    //     }
    //     cx_hash(ph, 0, G_context.signing_ctx.t_proofs.prevouts_sig_digest, 32, NULL, 0);
    //     if (G_context.signing_ctx.has_t_in) {
    //         cx_hash(ph, 0, G_context.signing_ctx.amount_hash, 32, NULL, 0);
    //         cx_hash(ph, 0, G_context.signing_ctx.t_proofs.scriptpubkeys_sig_digest, 32, NULL, 0);
    //     }
    //     cx_hash(ph, 0, G_context.signing_ctx.t_proofs.sequence_sig_digest, 32, NULL, 0);
    //     cx_hash(ph, 0, G_context.signing_ctx.t_outputs_hash, 32, NULL, 0);
    //     // transparent_hasher has transparent mid state
    // }
    // else {
    //     PRINTF(">> EMPTY TRANSPARENT BUNDLE\n");
    // }

    return 0;
}

int sapling_bundle_hash() {
    // cx_hash_t *ph = (cx_hash_t *) &G_context.hasher;
    // cx_blake2b_init2_no_throw(&G_context.hasher, 256,
    //                           NULL, 0,
    //                           (uint8_t *) "ZTxIdSOutputHash", 16);
    // if (G_context.signing_ctx.has_s_out) {                            
    //     cx_hash(ph, 0, G_context.signing_ctx.s_compact_hash, 32, NULL, 0);
    //     cx_hash(ph, 0, G_context.signing_ctx.s_proofs.sapling_outputs_memos_digest, 32, NULL, 0);
    //     cx_hash(ph, 0, G_context.signing_ctx.s_proofs.sapling_outputs_noncompact_digest, 32, NULL, 0);
    // }
    // cx_hash(ph,
    //         CX_LAST, NULL, 0,
    //         G_context.signing_ctx.sapling_bundle_hash, 32);
    // cx_blake2b_init2_no_throw(&G_context.hasher, 256,
    //                           NULL, 0,
    //                           (uint8_t *) "ZTxIdSaplingHash", 16);
    // if (G_context.signing_ctx.has_s_in || G_context.signing_ctx.has_s_out) {                              
    //     PRINTF(">> SAPLING BUNDLE: %.*H\n", 32, G_context.signing_ctx.s_proofs.sapling_spends_digest);
    //     PRINTF(">> SAPLING BUNDLE: %.*H\n", 32, G_context.signing_ctx.sapling_bundle_hash);
    //     PRINTF(">> SAPLING BUNDLE: %.*H\n", 8, (uint8_t *)&G_context.signing_ctx.s_net);
    //     cx_hash(ph, 0, G_context.signing_ctx.s_proofs.sapling_spends_digest, 32, NULL, 0);
    //     cx_hash(ph, 0, G_context.signing_ctx.sapling_bundle_hash, 32, NULL, 0);
    //     cx_hash(ph, 0, (uint8_t *)&G_context.signing_ctx.s_net, 8, NULL, 0);
    // }
    // else {
    //     PRINTF(">> EMPTY SAPLING BUNDLE\n");
    // }
    // cx_hash(ph, CX_LAST, NULL, 0, G_context.signing_ctx.sapling_bundle_hash, 32);
    // PRINTF("SAPLING BUNDLE: %.*H\n", 32, G_context.signing_ctx.sapling_bundle_hash);

    return 0;
}

/**
 * Picks up the sig_hash computation from step S.2g
 * 
*/
static int finish_sighash(uint8_t *sighash, const uint8_t *txin_sig_digest) {
    // cx_blake2b_t tx_t_hasher;
    // memmove(&tx_t_hasher, &G_context.signing_ctx.transparent_hasher, sizeof(cx_blake2b_t));
    // cx_hash_t *ph = (cx_hash_t *) &tx_t_hasher;
    // uint8_t transparent_hash[32];
    // if (txin_sig_digest)
    //     cx_hash(ph, 0, txin_sig_digest, 32, NULL, 0);
    // cx_hash(ph, CX_LAST, NULL, 0, transparent_hash, 32);

    // PRINTF("HEADER: %.*H\n", 32, G_context.signing_ctx.header_hash);
    // PRINTF("TRANSPARENT SIG BUNDLE: %.*H\n", 32, transparent_hash);

    // cx_blake2b_init2_no_throw(&tx_t_hasher, 256,
    //                           NULL, 0,
    //                           (uint8_t *) "ZcashTxHash_\xB4\xD0\xD6\xC2", 16); // BranchID
    // cx_hash(ph, 0, G_context.signing_ctx.header_hash, 32, NULL, 0);
    // cx_hash(ph, 0, transparent_hash, 32, NULL, 0);
    // cx_hash(ph, 0, G_context.signing_ctx.sapling_bundle_hash, 32, NULL, 0);
    // cx_hash(ph, CX_LAST, G_context.signing_ctx.orchard_bundle_hash, 32, sighash, 32);

    // PRINTF("SAPLING SIG BUNDLE: %.*H\n", 32, G_context.signing_ctx.sapling_bundle_hash);
    // PRINTF("ORCHARD SIG BUNDLE: %.*H\n", 32, G_context.signing_ctx.orchard_bundle_hash);
    // PRINTF("TXID: %.*H\n", 32, sighash);

    return 0;
}

int get_sighash(uint8_t *txin_sig_hash) {
    if (txin_sig_hash) {
        uint8_t sighash[32];
        finish_sighash(sighash, txin_sig_hash);
        return helper_send_response_bytes(sighash, 32);
    }
    return helper_send_response_bytes(G_context.signing_ctx.sapling_sig_hash, 32);
}

int sign_transparent() {
    if (G_context.signing_ctx.stage != SIGN) {
        reset_app();
        return io_send_sw(SW_BAD_STATE);
    }
    ui_display_processing("sign t");

    finish_sighash(G_store.sig_hash, G_context.txin_sig_digest);
    PRINTF("TRANSPARENT SIG HASH: %.*H\n", 32, G_store.sig_hash);

    derive_tsk(G_store.tsk, G_context.account);
    transparent_ecdsa(G_store.signature, G_store.tsk, G_store.sig_hash);

    ui_menu_main();
    return helper_send_response_bytes(G_store.signature, 64);
}

int sign_sapling() {
    if (G_context.signing_ctx.stage != SIGN) {
        reset_app();
        return io_send_sw(SW_BAD_STATE);
    }
    ui_display_processing("sign z");

    uint8_t signature[64];
    sapling_sign(signature, G_context.signing_ctx.sapling_sig_hash);

    PRINTF("signature %.*H\n", 64, signature);

    ui_menu_main();
    return helper_send_response_bytes(signature, 64);
}

// These hashes are checked against the client values. If there is a mismatch
// it indicates a miscalculation
int get_shielded_hashes() {
    memmove(G_store.out_buffer, G_context.signing_ctx.sapling_bundle_hash, 32);
    return helper_send_response_bytes(G_store.out_buffer, 32);
}

int prf_chacha(cx_chacha_context_t *rng, uint8_t *v, size_t len) {
    memset(v, 0, len);
    cx_chacha_update(rng, v, v, len);

    return 0;
}
