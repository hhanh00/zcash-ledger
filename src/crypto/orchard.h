#pragma once

#include "../types.h"

/// @brief Derive the account keys
/// @param account 
void orchard_derive_spending_key(int8_t account);

/// @brief Compute the note commitment
/// @param cmx Note commitment, 32 byte hash
/// @param address Destination address, 43 bytes = 11 (d) + 32 (pk_d)
/// @param value Amount in zat, 8 bytes
/// @param rseed Random seed, 32 bytes
/// @param rho Nullifier, 32 bytes
/// @return cx_err_t
int cmx(uint8_t *cmx, uint8_t *address, uint64_t value, uint8_t *rseed, uint8_t *rho);

/// @brief Sign the next orchard input
/// @param signature Returned signature, 64 bytes = r + s
void do_sign_orchard(uint8_t *signature);
