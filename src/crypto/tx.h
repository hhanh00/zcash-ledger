#pragma once

#include <stddef.h>   // size_t
#include <stdbool.h>  // bool
#include <stdint.h>   // uint*_t
#include "chacha.h"

#include "../types.h"

extern cx_chacha_context_t chacha_rseed_rng;
extern cx_chacha_context_t chacha_alpha_rng;

int prf_chacha(cx_chacha_context_t *rng, uint8_t *v, size_t len);

int change_stage(uint8_t new_stage);

/* These function MUST be called and in this order */
int init_tx();
int add_t_input_amount(uint64_t amount); // ZTxTrAmountsHash
int add_t_output(t_out_t *output, bool confirmation); // ZTxIdOutputsHash
int add_s_output(s_out_t *output, bool confirmation); // ZTxIdSOutC__Hash
int confirm_fee(bool confirmation); // Sapling and Orchard Bundle Hash

// These functions are optional but must be called before confirm_fee
int set_s_net(int64_t balance);

// Signing function, users must have confirmed the tx
int sign_transparent();
int sign_sapling();

// Verification
int get_shielded_hashes();

// Private
int prf_chacha(cx_chacha_context_t *rng, uint8_t *v, size_t len);
int get_sighash(uint8_t *txin_sig_hash);
