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

/**
 * Transparent outputs must be p2pkh
 * No memo fields
*/

/**
Summary of the txid definition and tx_sig_id
transparent inputs are signed on tx_sig_id
sapling inputs are signed on txid

For more info, refer to https://zips.z.cash/zip-0244 and the tx format v5

txid covers the complete tx "ZcashTxHash_" || CONSENSUS_BRANCH_ID

T.1: header_digest       (32-byte hash output) ZTxIdHeadersHash
    T.1a: version             (4-byte little-endian version identifier including overwinter flag)
    T.1b: version_group_id    (4-byte little-endian version group identifier)
    T.1c: consensus_branch_id (4-byte little-endian consensus branch id)
    T.1d: lock_time           (4-byte little-endian nLockTime value)
    T.1e: expiry_height       (4-byte little-endian block height)
T.2: transparent_digest  (32-byte hash output) ZTxIdTranspaHash
    T.2a: prevouts_digest (32-byte hash) ZTxIdPrevoutHash
        prev_tx_hash
        index
    T.2b: sequence_digest (32-byte hash) ZTxIdSequencHash
    T.2c: outputs_digest  (32-byte hash)
        amount
        script
            19 76 a9 14 (20-byte hash of output) 88 ac

T.3: sapling_digest      (32-byte hash output)
T.4: orchard_digest      (32-byte hash output)

tx_sig_id is used for signing a given input
- transparent bundle,
    In common: ZTxIdTranspaHash
        S.2a: hash_type                (1 byte)
        S.2b: prevouts_sig_digest      (32-byte hash) ZTxIdPrevoutHash
            hash all prevouts: (prev_tx_hash, index)
        S.2c: amounts_sig_digest       (32-byte hash) ZTxTrAmountsHash
            amounts: 8 bytes
        S.2d: scriptpubkeys_sig_digest (32-byte hash) ZTxTrScriptsHash
            19 76 a9 14 (20-byte hash of spend) 88 ac
        S.2e: sequence_sig_digest      (32-byte hash) ZTxIdSequencHash
            FF FF FF FF
        S.2f: outputs_sig_digest       (32-byte hash) ZTxIdOutputsHash
            19 76 a9 14 (20-byte hash of output) 88 ac

    Specific to an input
        S.2g: txin_sig_digest          (32-byte hash) Zcash___TxInHash
            S.2g.i:   prevout      (field encoding)
            S.2g.ii:  value        (8-byte signed little-endian)
            S.2g.iii: scriptPubKey (field encoding)
            S.2g.iv:  nSequence    (4-byte unsigned little-endian)
- sapling bundle, tx_sig_id == txid
    sapling_digest ZTxIdSaplingHash
    T.3a: sapling_spends_digest  (32-byte hash) ZTxIdSSpendsHash
        T.3a.i:  sapling_spends_compact_digest    (32-byte hash) ZTxIdSSpendCHash
            nullifiers
        T.3a.ii: sapling_spends_noncompact_digest (32-byte hash) ZTxIdSSpendNHash
            T.3a.ii.1: cv     (field encoding bytes)
            T.3a.ii.2: anchor (field encoding bytes)
            T.3a.ii.3: rk     (field encoding bytes)
    T.3b: sapling_outputs_digest (32-byte hash) ZTxIdSOutputHash
        T.3b.i:   sapling_outputs_compact_digest    (32-byte hash) ZTxIdSOutC__Hash
            T.3b.i.1: cmu                  (field encoding bytes)
            T.3b.i.2: ephemeral_key        (field encoding bytes)
            T.3b.i.3: enc_ciphertext[..52] (First 52 bytes of field encoding)
        T.3b.ii:  sapling_outputs_memos_digest      (32-byte hash) ZTxIdSOutM__Hash
        T.3b.iii: sapling_outputs_noncompact_digest (32-byte hash) ZTxIdSOutN__Hash
            T.3b.iii.1: cv                    (field encoding bytes)
            T.3b.iii.2: enc_ciphertext[564..] (post-memo Poly1305 AEAD tag of field encoding)
            T.3b.iii.3: out_ciphertext        (field encoding bytes)
    T.3c: valueBalance           (64-bit signed little-endian)
- orchard bundle ZTxIdOrchardHash
    Not present
*/

#include <stdint.h>   // uint*_t
#include <string.h>   // memset, explicit_bzero
#include <stdbool.h>  // bool
#include <lcx_blake2.h>
#include "os.h"

#include "../types.h"
#include "globals.h"
#include "txid.h"

cx_blake2b_t hasher_prevouts;
cx_blake2b_t hasher_amounts;
cx_blake2b_t hasher_outputs;
cx_blake2b_t hasher_trp_sig_midstate;

cx_blake2b_t hasher_compact;
cx_blake2b_t hasher_non_compact;
cx_blake2b_t hasher_memo;

uint8_t header_hash[32];
uint8_t prevouts_hash[32];
uint8_t amounts_hash[32];
uint8_t scriptpubkeys_sig_hash[32];
uint8_t sequences_hash[32];
uint8_t outputs_hash[32];
uint8_t transparent_hash[32];
uint8_t shielded_txin_hash[32];

uint8_t sapling_spend_compact_hash[32];
uint8_t sapling_spend_non_compact_hash[32];
uint8_t sapling_hash[32];

uint8_t orchard_hash[32];

uint8_t txid_hash[32];
uint8_t shielded_txid_hash[32];

uint8_t t_in_count;

const uint8_t TEST_INPUT_PKH[] = { 0xcb, 0xe3, 0x57, 0x94, 0x75, 0xf2, 0xc7, 0xed, 0x1f, 0xa8, 0x65, 0x03, 0x4f, 0x75, 0xb6, 0x8c, 0x0f, 0x23, 0xaa, 0x04 };

int init_tx_v5(uint32_t expiry_height) {
    cx_blake2b_t hasher_header;
    cx_blake2b_init2_no_throw(&hasher_header, 256, NULL, 0, (uint8_t *)"ZTxIdHeadersHash", 16);
    uint32_t data = 0x80000005;
    cx_hash((cx_hash_t *)&hasher_header, 0, (uint8_t *)&data, 4, NULL, 0); // version
    data = 0x26A7270A;
    cx_hash((cx_hash_t *)&hasher_header, 0, (uint8_t *)&data, 4, NULL, 0); // version_group_id
    data = 0xC2D6D0B4;
    cx_hash((cx_hash_t *)&hasher_header, 0, (uint8_t *)&data, 4, NULL, 0); // consensus_branch_id
    data = 0;
    cx_hash((cx_hash_t *)&hasher_header, 0, (uint8_t *)&data, 4, NULL, 0); // lock_time
    cx_hash((cx_hash_t *)&hasher_header, CX_LAST, (uint8_t *)&expiry_height, 4, header_hash, 32);
    PRINTF("HEADER HASH %.*H\n", 32, header_hash);

    t_in_count = 0;
    cx_blake2b_init2_no_throw(&hasher_prevouts, 256, NULL, 0, (uint8_t *)"ZTxIdPrevoutHash", 16);
    cx_blake2b_init2_no_throw(&hasher_amounts, 256, NULL, 0, (uint8_t *)"ZTxTrAmountsHash", 16);
    cx_blake2b_init2_no_throw(&hasher_outputs, 256, NULL, 0, (uint8_t *)"ZTxIdOutputsHash", 16);

    cx_hash_t *ph = (cx_hash_t *)&hasher_trp_sig_midstate; // use this hasher temporarily
    cx_blake2b_init2_no_throw(&hasher_trp_sig_midstate, 256, NULL, 0, (uint8_t *)"ZTxIdSaplingHash", 16);
    cx_hash(ph, CX_LAST, NULL, 0, sapling_hash, 32);
    PRINTF("SAPLING HASH %.*H\n", 32, sapling_hash);

    cx_blake2b_init2_no_throw(&hasher_trp_sig_midstate, 256, NULL, 0, (uint8_t *)"ZTxIdOrchardHash", 16);
    cx_hash(ph, CX_LAST, NULL, 0, orchard_hash, 32);
    PRINTF("ORCHARD HASH %.*H\n", 32, orchard_hash);

    cx_blake2b_init2_no_throw(&hasher_compact, 256, NULL, 0, (uint8_t *)"ZTxIdSSpendCHash", 16);
    cx_blake2b_init2_no_throw(&hasher_non_compact, 256, NULL, 0, (uint8_t *)"ZTxIdSSpendNHash", 16);

    return 0;
}

/* Input must come from the ledger account */
int add_transparent_input(t_in_t *tin) {
    cx_hash((cx_hash_t *)&hasher_prevouts, 0, (uint8_t *)&tin->prev_tx_hash, 32, NULL, 0); // prevooutpoint
    cx_hash((cx_hash_t *)&hasher_prevouts, 0, (uint8_t *)&tin->index, 4, NULL, 0); 
    cx_hash((cx_hash_t *)&hasher_amounts, 0, (uint8_t *)&tin->amount, 8, NULL, 0); 

    t_in_count++;
    return 0;
}

const uint32_t PAY2PKH_1 = 0x14A97619; // First part of the pay2pkh bitcoin script (reversed)
const uint16_t PAY2PKH_2 = 0xAC88; // Second part of the pay2pkh bitcoin script (reversed)

int add_transparent_output(t_out_t *tout) {
    cx_hash((cx_hash_t *)&hasher_outputs, 0, (uint8_t *)&tout->amount, 8, NULL, 0); // output amount
    cx_hash((cx_hash_t *)&hasher_outputs, 0, (uint8_t *)&PAY2PKH_1, 4, NULL, 0); // <size> OP_DUP OP_HASH160 <key size>
    cx_hash((cx_hash_t *)&hasher_outputs, 0, (uint8_t *)&tout->pkh, 20, NULL, 0); // pk hash
    cx_hash((cx_hash_t *)&hasher_outputs, 0, (uint8_t *)&PAY2PKH_2, 2, NULL, 0); // OP_EQUALVERIFY OP_CHECKSIG

    return 0;
}

int add_sapling_input(s_in_t *sin) {
    cx_hash((cx_hash_t *)&hasher_compact, 0, (uint8_t *)&sin->nullifier, 32, NULL, 0); // nullifier
    cx_hash((cx_hash_t *)&hasher_non_compact, 0, (uint8_t *)&sin->cv, 32, NULL, 0); // cv
    cx_hash((cx_hash_t *)&hasher_non_compact, 0, (uint8_t *)&sin->anchor, 32, NULL, 0); // anchor
    cx_hash((cx_hash_t *)&hasher_non_compact, 0, (uint8_t *)&sin->rk, 32, NULL, 0); // rk

    return 0;
}

int end_sapling_inputs() {
    cx_hash((cx_hash_t *)&hasher_compact, CX_LAST, NULL, 0, sapling_spend_compact_hash, 32); // nullifier
    cx_hash((cx_hash_t *)&hasher_non_compact, CX_LAST, NULL, 0, sapling_spend_non_compact_hash, 32); // nullifier

    cx_blake2b_init2_no_throw(&hasher_compact, 256, NULL, 0, (uint8_t *)"ZTxIdSOutC__Hash", 16);
    cx_blake2b_init2_no_throw(&hasher_non_compact, 256, NULL, 0, (uint8_t *)"ZTxIdSOutN__Hash", 16);
    cx_blake2b_init2_no_throw(&hasher_memo, 256, NULL, 0, (uint8_t *)"ZTxIdSOutM__Hash", 16);

    return 0;
}

int add_sapling_compact_output(s_out_compact_t *sout) {
    cx_hash((cx_hash_t *)&hasher_compact, 0, (uint8_t *)&sout->cmu, 32, NULL, 0); // cmu
    cx_hash((cx_hash_t *)&hasher_compact, 0, (uint8_t *)&sout->epk, 32, NULL, 0); // ephemeral key
    cx_hash((cx_hash_t *)&hasher_compact, 0, (uint8_t *)&sout->enc_compact, 52, NULL, 0); // light encrypted note

    return 0;
}

int add_sapling_memo_output(uint8_t *memo, size_t len) { 
    return 0;
}

int add_sapling_non_compact_output(s_out_non_compact_t *sout) {
    cx_hash((cx_hash_t *)&hasher_non_compact, 0, (uint8_t *)&sout->cv, 32, NULL, 0);
    cx_hash((cx_hash_t *)&hasher_non_compact, 0, (uint8_t *)&sout->aead, 16, NULL, 0);
    cx_hash((cx_hash_t *)&hasher_non_compact, 0, (uint8_t *)&sout->out_cipher, 80, NULL, 0);

    return 0;
}

int confirm_tx() {
    cx_hash((cx_hash_t *)&hasher_prevouts, CX_LAST, NULL, 0, prevouts_hash, 32);
    PRINTF("PREVOUTS HASH %.*H\n", 32, prevouts_hash);

    cx_hash((cx_hash_t *)&hasher_amounts, CX_LAST, NULL, 0, amounts_hash, 32);
    PRINTF("AMOUNTS %.*H\n", 32, amounts_hash);

    cx_blake2b_t hasher;
    cx_hash_t *ph = (cx_hash_t *)&hasher;

    cx_blake2b_init2_no_throw(&hasher, 256, NULL, 0, (uint8_t *)"ZTxTrScriptsHash", 16);
    for (uint8_t i = 0; i < t_in_count; i++) {
        cx_hash(ph, 0, (uint8_t *)&PAY2PKH_1, 4, NULL, 0); // <size> OP_DUP OP_HASH160 <key size>
        cx_hash(ph, 0, (uint8_t *)TEST_INPUT_PKH, 20, NULL, 0); // pk hash
        cx_hash(ph, 0, (uint8_t *)&PAY2PKH_2, 2, NULL, 0); // OP_EQUALVERIFY OP_CHECKSIG
    }
    cx_hash(ph, CX_LAST, NULL, 0, scriptpubkeys_sig_hash, 32);
    PRINTF("TRINSCRIPT HASH %.*H\n", 32, scriptpubkeys_sig_hash);

    cx_blake2b_init2_no_throw(&hasher, 256, NULL, 0, (uint8_t *)"ZTxIdSequencHash", 16);
    uint32_t sequence = 0xFFFFFFFF;
    for (uint8_t i = 0; i < t_in_count; i++) {
        cx_hash(ph, 0, (uint8_t *)&sequence, 4, NULL, 0); // sequence
    }
    cx_hash(ph, CX_LAST, NULL, 0, sequences_hash, 32);
    PRINTF("SEQUENCES HASH %.*H\n", 32, sequences_hash);

    cx_hash((cx_hash_t *)&hasher_outputs, CX_LAST, NULL, 0, outputs_hash, 32);
    PRINTF("OUTPUTS HASH %.*H\n", 32, outputs_hash);

    cx_blake2b_init2_no_throw(&hasher, 256, NULL, 0, (uint8_t *)"ZTxIdTranspaHash", 16);
    cx_hash(ph, 0, prevouts_hash, 32, NULL, 0);
    cx_hash(ph, 0, sequences_hash, 32, NULL, 0);
    cx_hash(ph, CX_LAST, outputs_hash, 32, transparent_hash, 32);
    PRINTF("TRANSPARENT HASH %.*H\n", 32, transparent_hash);

    // The beginning is the same for every transparent input sig hash
    ph = (cx_hash_t *)&hasher_trp_sig_midstate;
    cx_blake2b_init2_no_throw(&hasher_trp_sig_midstate, 256, NULL, 0, (uint8_t *)"ZTxIdTranspaHash", 16);
    uint8_t hash_type = 1;
    cx_hash(ph, 0, &hash_type, 1, NULL, 0);
    cx_hash(ph, 0, prevouts_hash, 32, NULL, 0);
    cx_hash(ph, 0, amounts_hash, 32, NULL, 0);
    cx_hash(ph, 0, scriptpubkeys_sig_hash, 32, NULL, 0);
    cx_hash(ph, 0, sequences_hash, 32, NULL, 0);
    cx_hash(ph, 0, outputs_hash, 32, NULL, 0);

    PRINTF("TRANSPARENT HASH\n", 32, transparent_hash);

    cx_blake2b_t hasher_sig_i;
    ph = (cx_hash_t *)&hasher_sig_i;
    cx_blake2b_init2_no_throw(&hasher_sig_i, 256, NULL, 0, (uint8_t *)"Zcash___TxInHash", 16);
    cx_hash(ph, CX_LAST, NULL, 0, shielded_txin_hash, 32); // replaces txin_sig_hash when signing sapling/orchard
    PRINTF("SHIELDED TXIN_SIG HASH %.*H\n", 32, shielded_txin_hash);

    ph = (cx_hash_t *)&hasher_sig_i; //  reuse
    cx_blake2b_init2_no_throw(&hasher_sig_i, 256, NULL, 0, (uint8_t *)"ZcashTxHash_\xB4\xD0\xD6\xC2", 16);
    cx_hash(ph, 0, header_hash, 32, NULL, 0);
    cx_hash(ph, 0, transparent_hash, 32, NULL, 0);
    cx_hash(ph, 0, sapling_hash, 32, NULL, 0);
    cx_hash(ph, CX_LAST, orchard_hash, 32, txid_hash, 32);
    PRINTF("TXID HASH %.*H\n", 32, txid_hash); // Non malleable txid - not for signing

    uint8_t sig_transparent_hash[32];
    ph = (cx_hash_t *)&hasher_sig_i; //  reuse
    memmove(&hasher_sig_i, &hasher_trp_sig_midstate, sizeof(cx_blake2b_t));
    cx_hash(ph, CX_LAST, (uint8_t *)shielded_txin_hash, 32, sig_transparent_hash, 32); // txin_sig_hash
    PRINTF("TRANSPARENT SIGHASH %.*H\n", 32, sig_transparent_hash);

    ph = (cx_hash_t *)&hasher_sig_i; //  reuse
    cx_blake2b_init2_no_throw(&hasher_sig_i, 256, NULL, 0, (uint8_t *)"ZcashTxHash_\xB4\xD0\xD6\xC2", 16);
    cx_hash(ph, 0, header_hash, 32, NULL, 0);
    cx_hash(ph, 0, sig_transparent_hash, 32, NULL, 0);
    cx_hash(ph, 0, sapling_hash, 32, NULL, 0);
    cx_hash(ph, CX_LAST, orchard_hash, 32, shielded_txid_hash, 32);
    PRINTF("SHIELDED_SIG TXID HASH %.*H\n", 32, shielded_txid_hash); // sighash for sapling & orchard

    return 0;
}

int sign_transparent_input(t_in_t *tin) {
    cx_blake2b_t hasher_sig_i;
    uint8_t sig_i_hash[32];

    cx_hash_t *ph = (cx_hash_t *)&hasher_sig_i;
    cx_blake2b_init2_no_throw(&hasher_sig_i, 256, NULL, 0, (uint8_t *)"Zcash___TxInHash", 16);
    cx_hash(ph, 0, (uint8_t *)&tin->prev_tx_hash, 32, NULL, 0); // prevoutpoint
    cx_hash(ph, 0, (uint8_t *)&tin->index, 4, NULL, 0); 
    cx_hash(ph, 0, (uint8_t *)&tin->amount, 8, NULL, 0);
    cx_hash(ph, 0, (uint8_t *)&PAY2PKH_1, 4, NULL, 0); // <size> OP_DUP OP_HASH160 <key size>
    cx_hash(ph, 0, (uint8_t *)TEST_INPUT_PKH, 20, NULL, 0); // pk hash
    cx_hash(ph, 0, (uint8_t *)&PAY2PKH_2, 2, NULL, 0); // OP_EQUALVERIFY OP_CHECKSIG
    uint32_t sequence = 0xFFFFFFFF;
    cx_hash(ph, CX_LAST, (uint8_t *)&sequence, 4, sig_i_hash, 32); // sequence
    PRINTF("TRANSPARENT TXIN_SIG HASH %.*H\n", 32, sig_i_hash);

    uint8_t sig_transparent_hash[32];
    memmove(&hasher_sig_i, &hasher_trp_sig_midstate, sizeof(cx_blake2b_t));
    cx_hash(ph, CX_LAST, (uint8_t *)sig_i_hash, 32, sig_transparent_hash, 32); // txin_sig_hash
    PRINTF("TRANSPARENT SIGHASH %.*H\n", 32, sig_transparent_hash);

    ph = (cx_hash_t *)&hasher_sig_i; //  reuse
    cx_blake2b_init2_no_throw(&hasher_sig_i, 256, NULL, 0, (uint8_t *)"ZcashTxHash_\xB4\xD0\xD6\xC2", 16);
    cx_hash(ph, 0, header_hash, 32, NULL, 0);
    cx_hash(ph, 0, sig_transparent_hash, 32, NULL, 0);
    cx_hash(ph, 0, sapling_hash, 32, NULL, 0);
    cx_hash(ph, CX_LAST, orchard_hash, 32, shielded_txid_hash, 32);
    PRINTF("TRANSPARENT TXID HASH %.*H\n", 32, shielded_txid_hash); // sighash for sapling & orchard

    return 0;
}

int finalize_tx() {
    return 0;

}
