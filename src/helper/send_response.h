#pragma once

#include "os.h"

#include "../common/macros.h"

/**
 * Length of fvk key.
 */
#define FVK_LEN (sizeof(fvk_ctx_t))

/**
 * Helper to send APDU response with fvk.
 *
 * response = FVK_LEN (1) ||
 *            G_context.fvk_info
 *
 * @return zero or positive integer if success, -1 otherwise.
 *
 */
int helper_send_response_fvk(void);

int helper_send_response_bytes(const u_int8_t *data, int data_len);
