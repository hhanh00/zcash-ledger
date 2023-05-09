#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

#include <lcx_blake2.h>
#include <lcx_sha256.h>
#include <lcx_ripemd160.h>
#include <ox_bn.h>
#include "constants.h"
#include "tx.h"
#include "ua.h"
#include "blake2s.h"
#include "sapling.h"

void check_canary_inner();

#ifdef ORCHARD
#define check_canary()
#else // Only check on NanoS
#define check_canary() check_canary_inner()
#endif

/**
 * Enumeration for the status of IO.
 */
typedef enum {
    READY,     /// ready for new event
    RECEIVED,  /// data received
    WAITING    /// waiting
} io_state_e;

/**
 * Enumeration with expected INS of APDU commands.
 */
typedef enum {
    GET_VERSION = 0x03,     /// version of the application
    GET_APP_NAME = 0x04,    /// name of the application
    INITIALIZE = 0x05,
    GET_PUBKEY = 0x06,
    GET_FVK = 0x07,         /// full viewing key (diversifiable viewing key)
    GET_OFVK = 0x08,        /// orchard fvk
    GET_PROOFGEN_KEY = 0x09,
    HAS_ORCHARD = 0x0A,
    INIT_TX = 0x10,
    CHANGE_STAGE = 0x11,
    ADD_T_IN = 0x12,
    ADD_T_OUT = 0x13,
    ADD_S_OUT = 0x14,
    ADD_O_ACTION = 0x15,
    SET_S_NET = 0x16,
    SET_O_NET = 0x17,
    SET_HEADER_DIGEST = 0x18,
    SET_T_MERKLE_PROOF = 0x19,
    SET_S_MERKLE_PROOF = 0x1A,
    SET_O_MERKLE_PROOF = 0x1B,
    CONFIRM_FEE = 0x1C,
    SIGN_TRANSPARENT = 0x21,
    SIGN_SAPLING = 0x22,
    SIGN_ORCHARD = 0x23,
    GET_S_SIGHASH = 0x24,
    END_TX = 0x30,
    GET_T_SIGHASH = 0x83,
    GET_DEBUG_BUFFER = 0xFE,
    TEST_MATH = 0xFF,
} command_e;

/**
 * Structure with fields of APDU command.
 */
typedef struct {
    uint8_t cla;    /// Instruction class
    command_e ins;  /// Instruction code
    uint8_t p1;     /// Instruction parameter 1
    uint8_t p2;     /// Instruction parameter 2
    uint8_t lc;     /// Length of command data
    uint8_t *data;  /// Command data
} command_t;

typedef uint8_t fr_t[32];
typedef uint8_t fq_t[32];
typedef uint8_t hash_t[32];
typedef uint8_t jubjub_point_t[32];
typedef uint8_t ovk_t[32];
typedef uint8_t dk_t[32];
typedef uint8_t div_t[11];

typedef uint8_t fp_t[32];
typedef uint8_t fv_t[32];

/**
 * Diversifiable viewing key
*/ 
typedef struct {
    fr_t ask;
    fr_t nsk;
    ovk_t ovk;
    dk_t dk;
    div_t d;
    uint8_t pk_d[32];
} expanded_spending_key_t;

/**
 * Diversifiable viewing key
 * We display it as a full viewing key because it has no official 
 * encoding
 * It is ok because we are not deriving any child key from it
*/
typedef struct {
    jubjub_point_t ak; // authorizing key
    jubjub_point_t nk; // nullifier key
} proofk_ctx_t;

typedef struct {
    jubjub_point_t ak; // authorizing key
    fr_t nsk; // nullifier key
} proofgen_key_t;

// typedef struct {
//     jubjub_point_t ak; // authorizing key
//     jubjub_point_t nk; // nullifier key
//     ovk_t ovk;
//     dk_t dk;
// } fvk_ctx_t;

typedef enum {
    IDLE,
    T_IN,
    T_OUT,
    S_OUT,
    O_ACTION,
    FEE,
    SIGN,
} signing_stage_t;

typedef struct {
    uint8_t pub_key[33];
    uint8_t pkh[20];
} transparent_key_t;

typedef struct {
    fv_t ask; // authorization key
    fp_t nk; // nullifier key
    fv_t rivk; // randomized ivk
    uint8_t ak[32]; // authorization public key
    uint8_t dk[32]; // diversifier key
    uint8_t ivk[32]; // incoming viewing key
    uint8_t div[11]; // default diversifier
    uint8_t pk_d[32]; // pk_d
    uint8_t address[43];
} orchard_key_t;

#ifdef ORCHARD
#define ORCHARD_ONLY(x) x
#else
#define ORCHARD_ONLY(x)
#endif

typedef struct {
    cx_blake2b_t hasher;
    cx_blake2b_t transparent_hasher;
    int64_t fee;
    uint64_t amount_s_out;
    ORCHARD_ONLY(uint64_t amount_o_out);
    int64_t t_net;
    int64_t s_net;
    int64_t o_net;
    uint8_t tsk[32];
    uint8_t amount_hash[32];
    uint8_t t_outputs_hash[32];
    uint8_t header_hash[32];
    t_proofs_t t_proofs;
    s_proofs_t s_proofs;
    ORCHARD_ONLY(o_proofs_t o_proofs);
    uint8_t s_compact_hash[32];
    uint8_t sapling_bundle_hash[32];
    ORCHARD_ONLY(uint8_t o_compact_hash[32]);
    uint8_t orchard_bundle_hash[32];
    uint8_t sapling_sig_hash[32];
    signing_stage_t stage;
    bool has_t_in;
    bool has_t_out;
    bool has_s_in;
    bool has_s_out;
    bool has_o_action;
} tx_signing_ctx_t;

typedef struct {
    cx_blake2b_t hasher;
} sapling_derive_ctx_t;

/**
 * Structure for global context.
 */
typedef struct {
    uint8_t account;
    union {
        t_out_t t_out;
        s_out_t s_out;
        o_action_t o_action;
    };
    bool keys_derived;
    sapling_derive_ctx_t sapling_derive_ctx;
    transparent_key_t transparent_key_info;
    expanded_spending_key_t exp_sk_info;
    #ifdef ORCHARD
    orchard_key_t orchard_key_info;
    #endif
    proofk_ctx_t proofk_info;
    tx_signing_ctx_t signing_ctx;
} global_ctx_t;

/// @brief  State of the Sapling Pedersen Hasher
typedef struct {
    uint8_t index_pack;
    uint8_t current_pack;
    int bits_in_pack;
    jj_e_t hash;
    cx_bn_t acc;
    cx_bn_t cur;
    cx_bn_t zero;
    cx_bn_t M;
} pedersen_state_t;

/// @brief Storage for temporary variables
/// that we cannot put on the stack because 
/// of limited space on Nano S
typedef struct {
    union {
        struct {
            cx_sha256_t sha_hasher;
            cx_ripemd160_t ripemd_hasher;
        };
        struct {
            blake2s_state hash_ctx;
            blake2s_param hash_params;
            uint8_t hash[32];
            pedersen_state_t ph;
            uint8_t Gdb[32];
        };
        struct {
            uint8_t receivers[UA_LEN];
            uint8_t bech32_buffer[2*UA_LEN];
        };
        struct {
            uint8_t out_buffer[128];
        };
        struct {
            char address[UA_LEN*2];
            char amount[23];
        };
    };
} temp_t;
