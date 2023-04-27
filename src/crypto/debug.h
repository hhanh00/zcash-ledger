#pragma once

#include "../types.h"

void init_debug();
void append_debug(uint8_t *data, size_t data_len);
int get_debug_buffer(uint8_t i);

