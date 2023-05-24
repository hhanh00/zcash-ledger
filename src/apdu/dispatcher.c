/*****************************************************************************
 *   Zcash Ledger App.
 *   (c) 2022 Hanh Huynh Huu.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>
#include <stdbool.h>

#include "dispatcher.h"
#include "../constants.h"
#include "../globals.h"
#include "../types.h"
#include "../io.h"
#include "../sw.h"
#include "../tx.h"
#include "../common/buffer.h"
#include "../crypto/transparent.h"
#include "../crypto/sapling.h"
#include "../crypto/tx.h"
#include "../ui/action/validate.h"
#include "../handler/test_math.h"
#include "../helper/send_response.h"

#include "../crypto/fr.h"
#include "../crypto/key.h"

#define MOVE_FIELD(s,field) memmove(&s.field, p, sizeof(s.field)); p += sizeof(s.field);
#define TRANSPARENT_OUT_LEN (8+1+20)

#ifdef TEST
#define OVERRIDE_CONFIRMATION(p) do { confirmation = p; } while(0);
#define OVERRIDE_RSEED(s)
#define OVERRIDE_ALPHA(a)
#else
#define OVERRIDE_CONFIRMATION(p) do { confirmation = true; } while(0);
#define OVERRIDE_RSEED(s) do { prf_chacha(&chacha_rseed_rng, s.rseed, 32); } while(0);
#define OVERRIDE_ALPHA(a) do { prf_chacha(&chacha_alpha_rng, a, 64); } while(0);
#endif

#define SAPLING_OUT_LEN (43+8+32+52+32)
#define ORCHARD_OUT_LEN (32+43+8+32+52+32)

const uint8_t VERSION[] = { 1, 0, 1 };

int apdu_dispatcher(const command_t *cmd) {
    if (cmd->cla != CLA) {
        return io_send_sw(SW_CLA_NOT_SUPPORTED);
    }

    uint8_t *p;
    bool confirmation;
    CHECK_STACK_ONLY(PRINTF("apdu_dispatcher stack %d\n", canary_depth(&confirmation)));
    switch (cmd->ins) {
        case GET_VERSION:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            return helper_send_response_bytes(VERSION, 3);

        case GET_APP_NAME:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            return helper_send_response_bytes((uint8_t *)"Zcash", 5);

        case INITIALIZE:
            if (cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            derive_keys(cmd->p1);
            check_canary();
            return io_send_sw(SW_OK);

        case GET_PUBKEY:
            if (cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != 0)
                return io_send_sw(SW_WRONG_DATA_LENGTH);

            derive_default_keys();
            return helper_send_response_bytes(G_context.transparent_key_info.pub_key, 33);

        case GET_FVK:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            {
            derive_default_keys();
            memmove(G_store.out_buffer, &G_context.proofk_info.ak, 32);
            memmove(G_store.out_buffer + 32, &G_context.proofk_info.nk, 32);
            memmove(G_store.out_buffer + 64, &G_context.exp_sk_info.ovk, 32);
            memmove(G_store.out_buffer + 96, &G_context.exp_sk_info.dk, 32);
            return helper_send_response_bytes(G_store.out_buffer, 128);
            }

        case GET_PROOFGEN_KEY: {
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            memmove(G_store.out_buffer, G_context.proofk_info.ak, 32);
            memmove(G_store.out_buffer + 32, G_context.exp_sk_info.nsk, 32);
            swap_endian(G_store.out_buffer + 32, 32);
            return helper_send_response_bytes(G_store.out_buffer, 64);
            }

        case SIGN_TRANSPARENT:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != 32)
                return io_send_sw(SW_WRONG_DATA_LENGTH);
            return sign_transparent(cmd->data);

        case SIGN_SAPLING:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != 64)
                return io_send_sw(SW_WRONG_DATA_LENGTH);

            return sign_sapling(cmd->data, cmd->data + 32);

        default:
            return io_send_sw(SW_INS_NOT_SUPPORTED);
    }
}
