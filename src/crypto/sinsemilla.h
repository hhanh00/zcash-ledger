#pragma once

#include <stdint.h>   // uint*_t
#include "fr.h"
#include "pallas.h"

typedef struct {
    jac_p_t p;
    uint16_t current_pack;
    int bits_in_pack;
} sinsemilla_state_t;

void init_sinsemilla(sinsemilla_state_t *state, jac_p_t *Q);
void hash_sinsemilla(sinsemilla_state_t *state, uint8_t *data, size_t data_bit_len);
void finalize_sinsemilla(sinsemilla_state_t *state, uint8_t *hash);

void sinsemilla_S(jac_p_t *S, uint32_t i);
