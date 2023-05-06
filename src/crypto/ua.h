#pragma once

#include "../types.h"

/// @brief Encode the derive UA - ~220 chars
/// @return 
int encode_my_ua();

/// @brief Encode the UA of a single Orchard receiver
/// @param orchard_address 
/// @return 
int encode_ua(uint8_t *orchard_address);
