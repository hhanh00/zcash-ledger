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
#include "sw.h"

#include "../globals.h"
#include "tx.h"
#include "../crypto/txid.h"
#include "../crypto/jubjub.h"
#include "../helper/send_response.h"

const uint8_t orchard_hash[] = {0x9F, 0xBE, 0x4E, 0xD1, 0x3B, 0x0C, 0x08, 0xE6, 0x71, 0xC1, 0x1A,
                                0x34, 0x07, 0xD8, 0x4E, 0x11, 0x17, 0xCD, 0x45, 0x02, 0x8A, 0x2E,
                                0xEE, 0x1B, 0x9F, 0xEA, 0xE7, 0x8B, 0x48, 0xA6, 0xE2, 0xC1};

cx_chacha_context_t chacha_rseed_rng;
cx_chacha_context_t chacha_alpha_rng;

int init_tx(uint8_t *header_digest) {
    memset(&G_context.signing_ctx, 0, sizeof(tx_signing_ctx_t));
    memmove(G_context.signing_ctx.header_hash, header_digest, 32);
    G_context.signing_ctx.stage = T_IN;
    cx_get_random_bytes(G_context.signing_ctx.mseed, 32);

    uint8_t seed_rng[32];
    cx_blake2b_init2_no_throw(&G_context.signing_ctx.hasher, 256,
                              NULL, 0,
                              (uint8_t *) "ZRSeedPRNG__Hash", 16);
    cx_hash((cx_hash_t *) &G_context.signing_ctx.hasher,
            CX_LAST,
            G_context.signing_ctx.mseed, 32,
            seed_rng, 32);

    cx_chacha_init(&chacha_rseed_rng, 20);
    cx_chacha_set_key(&chacha_rseed_rng, seed_rng, 32);

    cx_blake2b_init2_no_throw(&G_context.signing_ctx.hasher, 256,
                              NULL, 0,
                              (uint8_t *) "ZAlphaPRNG__Hash", 16);
    cx_hash((cx_hash_t *) &G_context.signing_ctx.hasher,
            CX_LAST,
            G_context.signing_ctx.mseed, 32,
            seed_rng, 32);

    PRINTF("ALPHA SEED: %.*H\n", 32, seed_rng);
    cx_chacha_init(&chacha_alpha_rng, 20);
    cx_chacha_set_key(&chacha_alpha_rng, seed_rng, 32);

    cx_blake2b_init2_no_throw(&G_context.signing_ctx.hasher,
                              256,
                              NULL,
                              0,
                              (uint8_t *) "ZTxTrAmountsHash",
                              16);

    return helper_send_response_bytes(G_context.signing_ctx.mseed, 32);
}

int change_stage(uint8_t new_stage) {
    switch (new_stage) {
        case T_OUT:
            cx_hash((cx_hash_t *) &G_context.signing_ctx.hasher,
                    CX_LAST,
                    NULL,
                    0,
                    G_context.signing_ctx.amount_hash,
                    32);
            PRINTF("T AMOUNTS: %.*H\n", 32, G_context.signing_ctx.amount_hash);
            cx_blake2b_init2_no_throw(&G_context.signing_ctx.hasher,
                                      256,
                                      NULL,
                                      0,
                                      (uint8_t *) "ZTxIdOutputsHash",
                                      16);
            break;
        case S_OUT:
            cx_hash((cx_hash_t *) &G_context.signing_ctx.hasher,
                    CX_LAST,
                    NULL,
                    0,
                    G_context.signing_ctx.t_outputs_hash,
                    32);
            PRINTF("T OUTPUTS: %.*H\n", 32, G_context.signing_ctx.t_outputs_hash);
            cx_blake2b_init2_no_throw(&G_context.signing_ctx.hasher,
                                      256,
                                      NULL,
                                      0,
                                      (uint8_t *) "ZTxIdSOutC__Hash",
                                      16);
            break;
        case S_NET:
            cx_hash((cx_hash_t *) &G_context.signing_ctx.hasher,
                    CX_LAST,
                    NULL,
                    0,
                    G_context.signing_ctx.s_compact_hash,
                    32);
            PRINTF("S OUTPUTS COMPACT: %.*H\n", 32, G_context.signing_ctx.s_compact_hash);
            break;
    }
    G_context.signing_ctx.stage = new_stage;

    return helper_send_response_bytes(NULL, 0);
}

const uint32_t PAY2PKH_1 = 0x14A97619;  // First part of the pay2pkh bitcoin script (reversed)
const uint16_t PAY2PKH_2 = 0xAC88;      // Second part of the pay2pkh bitcoin script (reversed)

int add_t_input_amount(uint64_t amount) {
    G_context.signing_ctx.has_t_in = true;
    cx_hash((cx_hash_t *) &G_context.signing_ctx.hasher, 0, (uint8_t *) &amount, 8, NULL, 0);

    return helper_send_response_bytes(NULL, 0);
}

int add_t_output(t_out_t *output) {
    G_context.signing_ctx.has_t_out = true;
    if (output->address_type != 0)  // only p2pkh for now
        return SW_INVALID_PARAM;

    cx_hash_t *ph = (cx_hash_t *) &G_context.signing_ctx.hasher;
    cx_hash(ph, 0, (uint8_t *) &output->amount, 8, NULL, 0);  // output amount
    cx_hash(ph, 0, (uint8_t *) &PAY2PKH_1, 4, NULL, 0);       // <size> OP_DUP OP_HASH160 <key size>
    cx_hash(ph, 0, output->address_hash, 20, NULL, 0);  // pk hash
    cx_hash(ph, 0, (uint8_t *) &PAY2PKH_2, 2, NULL, 0);              // OP_EQUALVERIFY OP_CHECKSIG

    return helper_send_response_bytes(NULL, 0);
}

int add_s_output(s_out_t *output) {
    uint8_t rseed[32];
    prf_chacha(&chacha_rseed_rng, rseed, 32);
    PRINTF("RSEED: %.*H\n", 32, rseed);

    uint8_t cmu[32];
    calc_cmu(cmu, output->address, rseed, output->amount);

    cx_hash_t *ph = (cx_hash_t *) &G_context.signing_ctx.hasher;
    cx_hash(ph, 0, cmu, 32, NULL, 0);           // cmu
    cx_hash(ph, 0, output->epk, 32, NULL, 0);  // ephemeral key
    cx_hash(ph, 0, output->enc, 52, NULL, 0);  // first 52 bytes of encrypted note

    return helper_send_response_bytes(NULL, 0);
}

int set_sapling_net(int64_t balance) {
    cx_hash_t *ph = (cx_hash_t *) &G_context.signing_ctx.hasher;
    cx_blake2b_init2_no_throw(&G_context.signing_ctx.hasher,
                              256,
                              NULL,
                              0,
                              (uint8_t *) "ZTxIdSOutputHash",
                              16);
    cx_hash(ph, 0, G_context.signing_ctx.s_compact_hash, 32, NULL, 0);
    cx_hash(ph, 0, G_context.signing_ctx.s_proofs.sapling_outputs_memos_digest, 32, NULL, 0);
    cx_hash(ph,
            CX_LAST,
            G_context.signing_ctx.s_proofs.sapling_outputs_noncompact_digest,
            32,
            G_context.signing_ctx.s_compact_hash,
            32);
    // s_compact_hash has sapling_outputs_digest
    cx_blake2b_init2_no_throw(&G_context.signing_ctx.hasher,
                              256,
                              NULL,
                              0,
                              (uint8_t *) "ZTxIdSaplingHash",
                              16);
    cx_hash(ph, 0, G_context.signing_ctx.s_proofs.sapling_spends_digest, 32, NULL, 0);
    cx_hash(ph, 0, G_context.signing_ctx.s_compact_hash, 32, NULL, 0);
    cx_hash(ph, CX_LAST, (uint8_t *) &balance, 8, G_context.signing_ctx.s_compact_hash, 32);
    // s_compact_hash has sapling_digest
    PRINTF("SAPLING BUNDLE: %.*H\n", 32, G_context.signing_ctx.s_compact_hash);

    cx_blake2b_init2_no_throw(&G_context.signing_ctx.hasher,
                              256,
                              NULL,
                              0,
                              (uint8_t *) "ZTxIdTranspaHash",
                              16);

    if (G_context.signing_ctx.has_t_in || G_context.signing_ctx.has_t_out) {
        if (G_context.signing_ctx.has_t_in) {
            uint8_t hash_type = 1;
            cx_hash(ph, 0, &hash_type, 1, NULL, 0);
        }
        cx_hash(ph, 0, G_context.signing_ctx.t_proofs.prevouts_sig_digest, 32, NULL, 0);
        if (G_context.signing_ctx.has_t_in) {
            cx_hash(ph, 0, G_context.signing_ctx.amount_hash, 32, NULL, 0);
            cx_hash(ph, 0, G_context.signing_ctx.t_proofs.scriptpubkeys_sig_digest, 32, NULL, 0);
        }
        cx_hash(ph, 0, G_context.signing_ctx.t_proofs.sequence_sig_digest, 32, NULL, 0);
        cx_hash(ph, 0, G_context.signing_ctx.t_outputs_hash, 32, NULL, 0);
        // hasher has transparent mid state
    }

    sighash(G_context.signing_ctx.sig_hash, NULL); // Compute the shielded sighash
    return helper_send_response_bytes(NULL, 0);
}

int set_t_merkle_proof(t_proofs_t *t_proofs) {
    memmove(&G_context.signing_ctx.t_proofs, t_proofs, sizeof(t_proofs_t));

    return helper_send_response_bytes(NULL, 0);
}

int set_s_merkle_proof(s_proofs_t *s_proofs) {
    memmove(&G_context.signing_ctx.s_proofs, s_proofs, sizeof(s_proofs_t));

    return helper_send_response_bytes(NULL, 0);
}

int sighash(uint8_t *sighash, uint8_t *txin_sig_digest) {
    cx_blake2b_t tx_t_hasher;
    memmove(&tx_t_hasher, &G_context.signing_ctx.hasher, sizeof(cx_blake2b_t));
    cx_hash_t *ph = (cx_hash_t *) &tx_t_hasher;
    uint8_t transparent_hash[32];
    if (txin_sig_digest) 
        cx_hash(ph, CX_LAST, txin_sig_digest, 32, transparent_hash, 32);
    else
        cx_hash(ph, CX_LAST, NULL, 0, transparent_hash, 32);

    PRINTF("TRANSPARENT SIG BUNDLE: %.*H\n", 32, transparent_hash);

    cx_blake2b_init2_no_throw(&tx_t_hasher,
                              256,
                              NULL,
                              0,
                              (uint8_t *) "ZcashTxHash_\xB4\xD0\xD6\xC2",
                              16);
    cx_hash(ph, 0, G_context.signing_ctx.header_hash, 32, NULL, 0);
    cx_hash(ph, 0, transparent_hash, 32, NULL, 0);
    cx_hash(ph, 0, G_context.signing_ctx.s_compact_hash, 32, NULL, 0);
    cx_hash(ph, CX_LAST, orchard_hash, 32, sighash, 32);

    PRINTF("TXID: %.*H\n", 32, sighash);

    return 0;
}

int get_sighash() {
    return helper_send_response_bytes(G_context.signing_ctx.sig_hash, 32);
}

int sign_sapling() {
    uint8_t alpha[64];
    prf_chacha(&chacha_alpha_rng, alpha, 64);
    fr_from_wide(alpha);
    PRINTF("ALPHA: %.*H\n", 32, alpha);

    fr_t ask;

    fr_add(&ask, &G_context.exp_sk_info.ask, (fr_t *)alpha);

    uint8_t msg[64];
    a_to_pk(msg, &ask); // first 32 bytes are re-randomized pk
    memmove(msg + 32, G_context.signing_ctx.sig_hash, 32);
    PRINTF("MSG: %.*H\n", 64, msg);

    uint8_t signature[64];
    sign(signature, &ask, msg);

    return helper_send_response_bytes(signature, 64);
}

int prf_chacha(cx_chacha_context_t *rng, uint8_t *v, size_t len) {
    memset(v, 0, len);
    cx_chacha_update(rng, v, v, len);

    return 0;
}
