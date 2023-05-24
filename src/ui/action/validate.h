#pragma once

#include <stdbool.h>  // bool

/**
 * Action for full viewing key validation and export.
 *
 * @param[in] choice
 *   User choice (either approved or rejected).
 *
 */
void validate_address(bool choice);

void reset_app();
