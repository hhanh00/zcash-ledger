#pragma once

#include <stddef.h>   // size_t
#include <stdbool.h>  // bool
#include <stdint.h>   // uint*_t

#include "../types.h"
#include "../common/buffer.h"

/**
 * Handler for GET_FULL_VIEWING_KEY command. 
 * Derive fvk and send APDU response.
 *
 * @return zero or positive integer if success, negative integer otherwise.
 */
int handler_get_address(bool display);
