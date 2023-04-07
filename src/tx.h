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
    uint8_t epk[32];
    uint8_t enc[52];
} s_out_t;
