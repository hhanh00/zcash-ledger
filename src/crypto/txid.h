#pragma once

#include "../tx.h"

int init_tx_v5();
int add_transparent_input(t_in_t *tin);
int add_transparent_output(t_out_t *tout);
int confirm_tx();
int sign_transparent_input(t_in_t *tin);
int finalize_tx();
