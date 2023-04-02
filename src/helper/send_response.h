#pragma once

#include "os.h"

#include "../common/macros.h"

/**
 * Helper to send APDU response with fvk.
 *
 * response = G_context.fvk_info
 *
 * @return zero or positive integer if success, -1 otherwise.
 *
 */
int helper_send_response_fvk(void);

int helper_send_response_address();

int helper_send_response_bytes(const u_int8_t *data, int data_len);
