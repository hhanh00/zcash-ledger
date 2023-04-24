#pragma once

#include <stdint.h>  // uint*_t

typedef struct {
    uint64_t amount;
    uint8_t address_type;
    uint8_t address_hash[20];
} t_out_t;

typedef struct {
    uint64_t amount;
    uint8_t epk[32];
    uint8_t address[43]; // 11 (d) + 32 (pk_d)
    uint8_t enc[52];
} s_out_t;

typedef struct {
    uint64_t amount;
    uint8_t nf[32]; // rho
    uint8_t epk[32];
    uint8_t address[43]; // 11 (d) + 32 (pk_d)
    uint8_t enc[52];
} o_action_t;

typedef struct {
    uint8_t prevouts_sig_digest[32];
    uint8_t scriptpubkeys_sig_digest[32];
    uint8_t sequence_sig_digest[32];
} t_proofs_t;

typedef struct {
    uint8_t sapling_spends_digest[32];
    uint8_t sapling_outputs_memos_digest[32];
    uint8_t sapling_outputs_noncompact_digest[32];
} s_proofs_t;

typedef struct {
    uint8_t orchard_anchor[32];
    uint8_t orchard_memos_digest[32];
    uint8_t orchard_noncompact_digest[32];
} o_proofs_t;
