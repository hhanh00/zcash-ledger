#pragma once

#include <stdint.h>   // uint*_t
#include "fr.h"
#include "pallas.h"

/// Sinsemilla Commitment

/// @brief  State of the Sinsemilla Hasher
typedef struct {
    jac_p_t p;
    uint16_t current_pack;
    int bits_in_pack;
} sinsemilla_state_t;

/// @brief Initialize 
/// @param state 
/// @param Q 
void init_sinsemilla(sinsemilla_state_t *state, jac_p_t *Q);

/// @brief Add some data to the hasher
/// @param state 
/// @param data 
/// @param data_bit_len Length is BITS
void hash_sinsemilla(sinsemilla_state_t *state, uint8_t *data, size_t data_bit_len);
void finalize_sinsemilla(sinsemilla_state_t *state, uint8_t *hash);

/// @brief Return S value (used internally by hasher)
/// @param S 
/// @param i 
void sinsemilla_S(jac_p_t *S, uint32_t i);

/// @brief Initialize the Sinemilla Hasher
/// @param state 
/// @param perso_M 
/// @param perso_len 
void init_commit(sinsemilla_state_t *state, uint8_t *perso_M, size_t perso_len);

/// @brief Finish and get the hash value
/// @param state 
/// @param perso_r Personalization
/// @param perso_len Length in bytes
/// @param v key
/// @param hash output hash value 
/// @remark state.p has the hash point
void finalize_commit(sinsemilla_state_t *state, uint8_t *perso_r, size_t perso_len, fv_t *v, uint8_t *hash);
