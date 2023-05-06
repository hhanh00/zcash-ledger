#pragma once

#include "../types.h"

/**
 * jumble encrypts the message into a cipher of the same size
 * there is no key and anyone can decrypt the message
 * the purpose is to obfuscate the message, not to hide it.
 * Unified Addresses use it to prevent "partial collision"
*/
int f4jumble(uint8_t *message, size_t len);
