#pragma once

#include "../types.h"

/// @brief Derive the transparent secret key
/// @param tsk 
/// @param account 
/// @return 
int derive_tsk(uint8_t *tsk, uint8_t account);

/// @brief derive keys using the default account (0)
void derive_default_keys();

/// @brief derive keys using the given account #
/// @param account 
void derive_keys(uint8_t account);
