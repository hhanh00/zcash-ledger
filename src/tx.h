#pragma once

#include <stdint.h>  // uint*_t

typedef struct {
    uint64_t amount;
    uint32_t index;
    uint8_t prev_tx_hash[32];
} t_in_t;

typedef struct {
    uint64_t amount;
    uint8_t pkh[20];
} t_out_t;

typedef struct {
    uint8_t nullifier[32];
    uint8_t cv[32];
    uint8_t anchor[32];
    uint8_t rk[32];
} s_in_t;

typedef struct {
    uint8_t cmu[32];
    uint8_t epk[32];
    uint8_t enc_compact[52]; // TODO: decrypt and verify address, amount & rseed
} s_out_compact_t;

typedef struct {
    uint8_t cv[32];
    uint8_t aead[16];
    uint8_t out_cipher[80]; // use ovk to recover plain note
} s_out_non_compact_t;

/*
typedef __attribute__((packed)) struct {
    uint32_t version;
    uint32_t version_group_id;
    uint32_t consensus_branch_id;
    uint32_t lock_time;
    uint32_t expiry_height;
} tx_header_t;

typedef __attribute__((packed)) struct {
    uint8_t hash_type;
    uint8_t prevouts_sig_digest[32];
    uint8_t amounts_sig_digest[32];
    uint8_t scriptpubkeys_sig_digest[32];
    uint8_t sequence_sig_digest[32];
    uint8_t outputs_sig_digest[32];
    uint8_t txin_sig_digest[32];
} transparent_sig_digest_t;

typedef __attribute__((packed)) struct {
    uint8_t tx_hash[32];
    uint32_t index;
    uint64_t amount;
} tx_t_in_t;

typedef __attribute__((packed)) struct {
    uint8_t address_ripemd_hash[32];
    uint64_t amount;
} tx_t_in_t;
*/


