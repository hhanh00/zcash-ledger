#pragma once

#include "fr.h"

int init_tx();
int add_t_input_amount(uint64_t amount);
int add_t_output(t_out_t *tout);
int get_rseed();
int add_s_output(s_out_t *tout);
int set_sapling_balance(int64_t value);
int transparent_merkle_proof(
    uint8_t *prevouts_sig_digest,
    uint8_t *scriptpubkeys_sig_digest,
    uint8_t *sequence_sig_digest,
    uint8_t *txin_sig_digest
);
int sapling_merkle_proof(
    uint8_t *sapling_spends_digest,
    uint8_t *sapling_outputs_memos_digest,
    uint8_t *sapling_outputs_noncompact_digest
);
int sign_t_in(t_in_t *tin);
int sign_s_in();

int calc_cmu(uint8_t *address, uint8_t *rseed, uint64_t value);
void pedersen_hash_cmu(uint64_t value, uint8_t *g_d, uint8_t *pk_d, fr_t *rcm);
