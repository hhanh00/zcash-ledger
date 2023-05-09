#pragma once

#include "../types.h"

#ifdef ORCHARD
#define ORCHARD_LEN (2+43)
#else
#define ORCHARD_LEN 0
#endif

#define UA_LEN (2+20+2+43+ORCHARD_LEN+16)

/// @brief Encode the derive UA - ~220 chars
/// @return 
int encode_my_ua();

/// @brief Encode the UA of a single Orchard receiver
/// @param orchard_address 
/// @return 
int encode_ua(uint8_t *orchard_address);
