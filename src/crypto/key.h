#pragma once

#include "../types.h"

int derive_tsk(uint8_t *tsk, uint8_t account);
int derive_ssk(uint8_t *ssk, uint8_t account);
int derive_taddress(uint8_t *pkh, uint8_t account);
int derive_pubkey(uint8_t *pk, uint8_t account);

/// @brief derive the expanded spending key
/// @param exp_sk 
void crypto_derive_spending_key(int8_t account);

/// @brief calculate the incoming viewing key
/// @param ivk 
/// @param ak 
/// @param nk 
void calc_ivk(uint8_t *ivk, const uint8_t *ak, const uint8_t *nk);

/// @brief serialize a sapling address (d, pk_d) to a bech32 string
/// @param address 
/// @param d 
/// @param pk_d 
void to_address_bech32(char *address, uint8_t *d, uint8_t *pk_d);

int get_proofgen_key();

