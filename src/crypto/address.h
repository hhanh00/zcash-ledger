#pragma once

/// @brief serialize a sapling address (d, pk_d) to a bech32 string
/// @param address 
/// @param d 
/// @param pk_d 
void to_address_bech32(char *address, uint8_t *d, uint8_t *pk_d);

void to_t_address(char *out_address, uint8_t *kh);

