#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

#include <lcx_blake2.h>
#include "constants.h"
#include "tx.h"

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
    BUILD = 0x05,
    GET_FVK = 0x06,         /// full viewing key (diversifiable viewing key)
    GET_ADDRESS = 0x07,
    INIT_TX = 0x08,
    ADD_T_IN = 0x09,
    ADD_T_OUT = 0x0A,
    ADD_S_OUT = 0x0B,
    SET_S_NET = 0x0C,
    SET_T_MERKLE_PROOF = 0x0D,
    SET_S_MERKLE_PROOF = 0x0E,
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

/**
 * Enumeration with parsing state.
 */
typedef enum {
    STATE_NONE,     /// No state
    STATE_PARSED,   /// Transaction data parsed
    STATE_APPROVED  /// Transaction data approved
} state_e;

/**
 * Enumeration with user request type.
 */
typedef enum {
    CONFIRM_ADDRESS,     /// confirm address derived from public key
    CONFIRM_TRANSACTION  /// confirm transaction information
} request_type_e;

typedef uint8_t fr_t[32];
typedef uint8_t fq_t[32];
typedef uint8_t hash_t[32];
typedef uint8_t jubjub_point_t[32];
typedef uint8_t ovk_t[32];
typedef uint8_t dk_t[32];
typedef uint8_t div_t[11];

/**
 * Diversifiable viewing key
*/ 
typedef struct {
    jubjub_point_t ask;
    jubjub_point_t nsk;
    ovk_t ovk;
    dk_t dk;
    div_t d;
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
    jubjub_point_t nk; // nullifier key
    ovk_t ovk;
    dk_t dk;
} fvk_ctx_t;

/**
 * Structure for global context.
 */
typedef struct {
    state_e state;  /// state of the context
    uint8_t account;
    expanded_spending_key_t exp_sk_info;
    proofk_ctx_t proofk_info;
    char address[80];
    request_type_e req_type;              /// user request
} global_ctx_t;

typedef struct {
    uint8_t header[32];
} tx_hashes_t;

typedef struct {
    uint8_t rseed[32];
    cx_blake2b_t hasher;
    uint8_t amount_hash[32];
    t_proofs_t t_proofs;
    s_proofs_t s_proofs;
    int64_t s_net;
    uint8_t s_compact_hash[32];
} tx_signing_ctx_t;
