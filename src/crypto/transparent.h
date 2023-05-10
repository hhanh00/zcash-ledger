#pragma once

#include "../types.h"

/// @brief Derive the transparent address
/// @param pkh public key hash, 20 bytes
/// @param account 
/// @return 
int derive_taddress(uint8_t *pkh, uint8_t account);

/// @brief Derive the public key
/// @param pk public key, 33 bytes
/// @param account 
/// @return 
int derive_pubkey(uint8_t *pk, uint8_t account);

/// @brief Derive transparent keys
/// @param account 
/// @return 
int transparent_derive_pubkey(uint8_t account);
