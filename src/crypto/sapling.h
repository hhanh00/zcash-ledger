#pragma once

#include <stdint.h>   // uint*_t

void sapling_derive_spending_key(uint8_t account);
void get_cmu(uint8_t *cmu, uint8_t *d, uint8_t *pkd, uint64_t value, uint8_t *rseed);
void sapling_sign(uint8_t *signature, uint8_t *sig_hash);

typedef struct {
    cx_bn_t u;
    cx_bn_t v;
    cx_bn_t z;
    cx_bn_t t1;
    cx_bn_t t2;
} jj_e_t; // jubjub extended

typedef struct {
    cx_bn_t vpu; // v+u
    cx_bn_t vmu; // v-u
    cx_bn_t z;   // z
    cx_bn_t t2d; // t1.t2.2d
} jj_en_t; // jubjub extended niels

typedef struct {
    uint8_t vpu[32]; // v+u
    uint8_t vmu[32]; // v-u
    uint8_t z[32];   // z
    uint8_t t2d[32]; // t1.t2.2d
} ff_jj_en_t; // same as jj_en_t without BN

/// @brief Generator point for the spending authorization key pair
/// in Niels form
static const ff_jj_en_t SPENDING_GEN = {
    .vpu =
        {
            0x60, 0xC7, 0xD6, 0x91, 0x8E, 0x43, 0x7D, 0x88, 0x27, 0xD3, 0xDF,
            0xCF, 0xE8, 0x92, 0x38, 0x70, 0x43, 0x1F, 0x0F, 0x21, 0xBE, 0x6A,
            0x05, 0xE3, 0x78, 0x15, 0x79, 0x3F, 0xB5, 0x88, 0x5C, 0x83,
        },
    .vmu =
        {
            0x4E, 0x7A, 0x2C, 0xAB, 0x4D, 0x8F, 0xEF, 0x62, 0x7F, 0xA2, 0x8F,
            0xD1, 0x9B, 0xA7, 0xC1, 0x9A, 0x97, 0xAB, 0xBF, 0x79, 0xDF, 0x4D,
            0xB5, 0x94, 0xE8, 0x96, 0xEC, 0x1B, 0xA0, 0x5D, 0x0D, 0xDD,
        },
    .z =
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        },
    .t2d =
        {
            0x2A, 0xB8, 0xC1, 0x5A, 0x55, 0x5F, 0x87, 0x63, 0xBE, 0x33, 0xBD,
            0x80, 0x2D, 0xC5, 0xB5, 0x95, 0x7B, 0x5E, 0xDB, 0x80, 0x18, 0xB4,
            0xF8, 0x1F, 0xCB, 0x6A, 0xCE, 0xF9, 0x5B, 0x05, 0x8A, 0x6B,
        },
};

/// @brief Generator point for the nullifier key pair
/// in Niels form
static const ff_jj_en_t PROOF_GEN = {
    .vpu =
        {
            0x69, 0x0E, 0x76, 0x09, 0x4A, 0xAD, 0x0D, 0x5A, 0x4F, 0x0C, 0x05,
            0x75, 0xF7, 0xD9, 0xA9, 0x4D, 0xFE, 0xD2, 0x22, 0x23, 0xE8, 0x9D,
            0x01, 0xF2, 0x81, 0x6D, 0xD5, 0xE7, 0x99, 0xCC, 0x0E, 0x58,
        },
    .vmu =
        {
            0x40, 0x5F, 0x2C, 0x04, 0xE7, 0x11, 0x47, 0x9B, 0x6E, 0x85, 0xFD,
            0x92, 0x26, 0xB8, 0xE8, 0x4A, 0xA2, 0xEC, 0x81, 0xB2, 0x02, 0xA5,
            0x91, 0xB2, 0x0B, 0x88, 0x1E, 0x08, 0x26, 0xEF, 0xC3, 0x76,
        },
    .z =
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        },
    .t2d =
        {
            0x56, 0xF7, 0x9F, 0x1B, 0xF5, 0x6A, 0x37, 0x96, 0xF9, 0xF8, 0xBA,
            0x5D, 0x92, 0x6C, 0x61, 0x23, 0x9A, 0x1F, 0x8B, 0x0B, 0x25, 0x6E,
            0x74, 0x8A, 0xDD, 0x79, 0x02, 0xCD, 0x81, 0x22, 0x33, 0x7C,
        },
};

static const ff_jj_en_t PH_GENS[] = {
    {
        .vpu =
            {
                0x28, 0x70, 0xF6, 0xF3, 0xD7, 0xA2, 0x33, 0x87, 0xFC, 0x79, 0x64,
                0x41, 0xF8, 0x9D, 0xE7, 0xD1, 0xD4, 0x95, 0xFC, 0x18, 0x2F, 0x5F,
                0xA5, 0x10, 0x91, 0x0D, 0xEE, 0x67, 0xA1, 0x8A, 0x58, 0x1A,
            },
        .vmu =
            {
                0x28, 0xCC, 0x18, 0x51, 0xCF, 0x02, 0x03, 0x26, 0xF7, 0x18, 0xC8,
                0x95, 0x0E, 0x5F, 0xD0, 0xEC, 0x1D, 0xF8, 0x60, 0xFF, 0x51, 0x3C,
                0xE7, 0x54, 0x5E, 0x71, 0x69, 0x40, 0xC2, 0xBE, 0x21, 0x7A,
            },
        .z =
            {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            },
        .t2d =
            {
                0x67, 0x55, 0xAD, 0x20, 0x6C, 0x94, 0x59, 0xDE, 0x5A, 0x9A, 0xEA,
                0x90, 0x54, 0x01, 0x15, 0x5D, 0x92, 0xAE, 0xCD, 0x74, 0x5F, 0xFA,
                0x34, 0x3B, 0x8C, 0xF8, 0x9F, 0x23, 0xE6, 0x97, 0x61, 0x9C,
            },
    },
    {
        .vpu =
            {
                0x17, 0x00, 0xF9, 0x9E, 0x6A, 0x7D, 0x0B, 0xBC, 0x4A, 0x2C, 0x6B,
                0xCE, 0xD9, 0x0A, 0xB6, 0xAC, 0xC2, 0x9C, 0xAD, 0x2B, 0x6D, 0x8A,
                0xB3, 0x60, 0x34, 0x8F, 0x63, 0x04, 0x7C, 0x4F, 0x79, 0x0F,
            },
        .vmu =
            {
                0x5F, 0xA7, 0xC6, 0xB3, 0x75, 0xA8, 0x6D, 0xF3, 0xD8, 0x1F, 0x8E,
                0xBE, 0xB0, 0x9A, 0xD3, 0xA2, 0xCF, 0x96, 0x74, 0xAE, 0xC4, 0x69,
                0x50, 0x6F, 0xC1, 0x8C, 0x27, 0x73, 0x21, 0x2E, 0xB8, 0x14,
            },
        .z =
            {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            },
        .t2d =
            {
                0x1D, 0x95, 0x77, 0xE7, 0x1A, 0x15, 0x30, 0xBD, 0x76, 0x13, 0xE1,
                0xBE, 0xFE, 0x13, 0x34, 0xEA, 0x4A, 0x3B, 0xCB, 0xA2, 0xB0, 0xBB,
                0x1C, 0xAB, 0xBB, 0xAD, 0x22, 0xD9, 0x32, 0xC1, 0xFD, 0x15,
            },
    },
    {
        .vpu =
            {
                0x28, 0x83, 0x8F, 0x53, 0x2A, 0xF8, 0x54, 0x4D, 0x98, 0x30, 0x7A,
                0x9E, 0x7A, 0xB3, 0x52, 0x5E, 0xF2, 0xDD, 0x6C, 0x40, 0x7D, 0xC8,
                0x06, 0xF5, 0xF7, 0xC4, 0x47, 0xF0, 0x4E, 0x13, 0x98, 0xCB,
            },
        .vmu =
            {
                0x43, 0xD8, 0x9A, 0xAE, 0x79, 0xA5, 0x88, 0xF0, 0x27, 0xD0, 0xCE,
                0x3A, 0xA2, 0x66, 0x7E, 0x48, 0x24, 0x86, 0xE8, 0xBD, 0xB1, 0x41,
                0x62, 0x3B, 0x0A, 0x16, 0x58, 0x68, 0xE1, 0x14, 0x0F, 0xE3,
            },
        .z =
            {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            },
        .t2d =
            {
                0x46, 0x14, 0x0A, 0x22, 0x89, 0x32, 0x2C, 0x72, 0x28, 0xDC, 0x28,
                0x66, 0xF7, 0x84, 0x36, 0xA5, 0x24, 0x79, 0x17, 0x70, 0xD0, 0xED,
                0x70, 0xE2, 0x1D, 0xEC, 0xBD, 0x8B, 0xAE, 0x33, 0x3F, 0x91,
            },

    },
    {
        .vpu =
            {
                0x61, 0xB9, 0x49, 0x55, 0x19, 0xF4, 0x63, 0x4F, 0x7E, 0xCC, 0xFF,
                0x75, 0xA8, 0xCB, 0xE7, 0x8C, 0xCE, 0x06, 0x84, 0xB0, 0x06, 0x6A,
                0xF2, 0x77, 0xD0, 0xE7, 0xC3, 0xF1, 0x64, 0xFA, 0x13, 0xB5,
            },
        .vmu =
            {
                0x71, 0x32, 0x26, 0x16, 0xA6, 0x56, 0xAF, 0xA9, 0xD6, 0x7A, 0xEE,
                0x2A, 0x12, 0x88, 0x7F, 0xE7, 0x27, 0xBE, 0x7E, 0x96, 0x3B, 0xD2,
                0x3E, 0x92, 0x37, 0xFA, 0xD3, 0xE6, 0xE1, 0x70, 0xCE, 0x1E,
            },
        .z =
            {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            },
        .t2d =
            {
                0x0F, 0xC6, 0x38, 0xEF, 0xE1, 0x1C, 0x83, 0x01, 0xF2, 0x9B, 0x82,
                0xC5, 0x6B, 0xAA, 0xB8, 0xC1, 0xFC, 0x72, 0x79, 0x39, 0x01, 0x8B,
                0xA4, 0x79, 0x5D, 0xEA, 0xE8, 0x54, 0x64, 0x90, 0x40, 0x22,
            },
    }};

static const ff_jj_en_t CMU_RAND_GEN = {
    .vpu =
        {
            0x38, 0x37, 0x14, 0x8C, 0x4B, 0xD7, 0x76, 0xE4, 0x35, 0xDE, 0x11,
            0xE9, 0x61, 0x62, 0x18, 0xC2, 0x87, 0x49, 0x28, 0xF1, 0xFA, 0x4E,
            0xB1, 0x27, 0x7A, 0x10, 0x9E, 0x9A, 0x22, 0x4F, 0xDC, 0x0E,
        },
    .vmu =
        {
            0x5E, 0x4D, 0x7C, 0xCA, 0x37, 0xE6, 0x9F, 0x13, 0x26, 0x96, 0xB4,
            0xAD, 0x84, 0x8C, 0x18, 0x6D, 0xF9, 0xE3, 0x92, 0xE6, 0xFA, 0xE9,
            0x33, 0x71, 0x2F, 0xE8, 0x28, 0x2F, 0xD0, 0x89, 0x13, 0x4B,
        },
    .z =
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        },
    .t2d =
        {
            0x66, 0x15, 0x2E, 0x6D, 0x5A, 0xCB, 0xBE, 0xCA, 0x1A, 0x4C, 0xA7,
            0x39, 0x89, 0x6E, 0x7A, 0xD3, 0x35, 0x0E, 0xDC, 0xC3, 0x02, 0xF8,
            0xB6, 0x9D, 0x5D, 0xA6, 0x98, 0xAB, 0x5B, 0x20, 0xDC, 0x0A,
        },
};
