#pragma once

#include <stdint.h>  // uint*_t

typedef struct {
    uint64_t amount;
    uint32_t index;
    uint8_t prevout[32];
} t_in_t;

typedef struct {
    uint64_t amount;
    uint8_t address_type;
    uint8_t address_hash[20];
} t_out_t;

typedef struct {
    uint64_t amount;
    uint8_t epk[32];
    uint8_t address[48]; // 43 + some padding
    uint8_t enc[52];
} s_out_t;

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
