#pragma once

#include "../types.h"

/// @brief point on JJ given by u,v coordinates
/// -u^2 + v^2 = 1 + d.u^2.v^2 where d is a constant parameter
typedef struct {
    fq_t u;
    fq_t v;
} affine_point_t;

/// @brief extended point on JJ
/// we have T1 * T2 = UV/Z
/// and u = U/Z and v = V/Z
typedef struct {
    fq_t u;
    fq_t v;
    fq_t z;
    fq_t t1;
    fq_t t2;
} extended_point_t;

/// @brief extended niels point on JJ
/// vpu = V+U
/// vmu = V-U
/// z = Z
/// t2d = T1*T2*2*D
typedef struct {
    fq_t vpu;
    fq_t vmu;
    fq_t z;
    fq_t t2d;
} extended_niels_point_t;

/// @brief Generator point for the spending authorization key pair
/// in Niels form
static const extended_niels_point_t SPENDING_GENERATOR_NIELS = {
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
static const extended_niels_point_t PROOF_GENERATOR_NIELS = {
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

/// @brief Set to the identity point
/// @param v extended point
void ext_set_identity(extended_point_t *v);

/// @brief Set to the identity point
/// @param v extended Niels point
void extn_set_identity(extended_niels_point_t *v);

void ext_to_niels(extended_niels_point_t *v, const extended_point_t *a);

/// @brief v+v -> v
/// @param v 
void ext_double(extended_point_t *v);

/// @brief v + a -> v
/// @param v 
/// @param a 
/// Note that a is a extended Niels point but v is not
void ext_add(extended_point_t *v, const extended_niels_point_t *a);

/// @brief convert a point to a 32-byte value
/// @param v v coordinate of a with sign of u encoded in highest bit
/// @param a 
void ext_to_bytes(uint8_t *v, const extended_point_t *a);

void ext_to_u(uint8_t *u, const extended_point_t *a);

/// @brief convert a 32-byte array to a point
/// It fails if there is no point that has a v coordinate == a 
/// @param v 
/// @param a 
/// @return CX_OK success, 
///         CX_INVALID_PARAMETER a does not match a point on JJ
int extn_from_bytes(extended_niels_point_t *v, const uint8_t *a);

/// @brief multiply base by x
/// This is the trapdoor function to go from secret key to public key
/// @param v 
/// @param base 
/// @param x 
void ext_base_mult(extended_point_t *v, const extended_niels_point_t *base, fr_t *x);

/// @brief hashes an array of len bytes
/// @param hash hash value (may not belong to JJ)
/// @param data pointer to the beginning of the array
/// @param len length of the array
void jubjub_hash(uint8_t *hash, const uint8_t *data, size_t len);

/// @brief compute a public key by multiplying the generator gen with sk
/// @param pk 
/// @param gen 
/// @param sk 
void jubjub_to_pk(uint8_t *pk, const extended_niels_point_t *gen, fr_t *sk);

/// @brief helper function to go from ask to ak (authorization)
/// @param ak 
/// @param ask 
static inline void a_to_pk(uint8_t *ak, fr_t *ask) {
    jubjub_to_pk(ak, &SPENDING_GENERATOR_NIELS, ask);
}

/// @brief helper function to go from nsk to nk (nullifier)
/// @param nk 
/// @param nsk 
static inline void n_to_pk(uint8_t *nk, fr_t *nsk) {
    jubjub_to_pk(nk, &PROOF_GENERATOR_NIELS, nsk);
}
