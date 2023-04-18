#pragma once

#include <stdbool.h>  // bool
#include "../tx.h"

/**
 * Callback to reuse action with approve/reject in step FLOW.
 */
typedef void (*action_validate_cb)(bool);

/**
 * Display address on the device and ask confirmation to export.
 *
 * @return 0 if success, negative integer otherwise.
 *
 */
int ui_display_address(void);

int ui_display_processing();
int ui_confirm_t_out(t_out_t *s_out);
int ui_confirm_s_out(s_out_t *s_out);
int ui_confirm_fee(int64_t fee);
