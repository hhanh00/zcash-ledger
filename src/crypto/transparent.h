#pragma once

#include "../types.h"

int derive_tsk(uint8_t *tsk, uint8_t account);
int derive_ssk(uint8_t *ssk, uint8_t account);
int derive_taddress(uint8_t *pkh, uint8_t account);
int derive_pubkey(uint8_t *pk, uint8_t account);

