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
#include "../crypto/orchard.h"
#include "../crypto/tx.h"
#include "../ui/action/validate.h"
#include "../handler/test_math.h"
#include "../helper/send_response.h"

#include "../crypto/fr.h"
#include "../crypto/prf.h"
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
    uint8_t has_orchard = 0;
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

        case GET_OFVK: {
            #ifdef ORCHARD
            derive_default_keys();
            memmove(G_store.out_buffer, G_context.orchard_key_info.ak, 32);
            memmove(G_store.out_buffer + 32, G_context.orchard_key_info.nk, 32);
            swap_endian(G_store.out_buffer + 32, 32);
            memmove(G_store.out_buffer + 64, G_context.orchard_key_info.rivk, 32);
            swap_endian(G_store.out_buffer + 64, 32);
            return helper_send_response_bytes(G_store.out_buffer, 96);
            #else
            return io_send_sw(SW_INS_NOT_SUPPORTED);
            #endif
        }

        case HAS_ORCHARD: {
            #ifdef ORCHARD
            has_orchard = 1;
            #endif
            return helper_send_response_bytes(&has_orchard, 1);
        }

        case INIT_TX:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != 0)
                return io_send_sw(SW_WRONG_DATA_LENGTH);

            return init_tx();

        case ADD_T_IN:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != 8)
                return io_send_sw(SW_WRONG_DATA_LENGTH);

            p = cmd->data;
            uint64_t amount;
            memmove(&amount, p, 8);
            return add_t_input_amount(amount);

        case ADD_T_OUT:
            if (cmd->p1 > 1 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != TRANSPARENT_OUT_LEN)
                return io_send_sw(SW_WRONG_DATA_LENGTH);

            OVERRIDE_CONFIRMATION(cmd->p1);
            {
                memset(&G_context.t_out, 0, sizeof(t_out_t));
                p = cmd->data;

                MOVE_FIELD(G_context.t_out, amount);
                MOVE_FIELD(G_context.t_out, address_type);
                MOVE_FIELD(G_context.t_out, address_hash);

                // Check parameters, any address_hash is technically valid
                CHECK_MONEY(G_context.t_out.amount);
                if (G_context.t_out.address_type != 0)
                    return io_send_sw(SW_INVALID_PARAM);

                return add_t_output(&G_context.t_out, confirmation);
            }

        case ADD_S_OUT:
            if (cmd->p1 > 1 || cmd->p2 > 1) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != SAPLING_OUT_LEN && cmd->lc != SAPLING_OUT_LEN - 32)
                return io_send_sw(SW_WRONG_DATA_LENGTH);

            OVERRIDE_CONFIRMATION(cmd->p1);
            {
                memset(&G_context.s_out, 0, sizeof(s_out_t));
                p = cmd->data;

                MOVE_FIELD(G_context.s_out, address);
                MOVE_FIELD(G_context.s_out, amount);
                MOVE_FIELD(G_context.s_out, epk);
                MOVE_FIELD(G_context.s_out, enc);
                if (cmd->lc == SAPLING_OUT_LEN)
                    MOVE_FIELD(G_context.s_out, rseed);

                // in prod, rseed is picked by our PRNG, not the client's
                OVERRIDE_RSEED(G_context.s_out);

                // Check parameters
                // diversifier is checked later
                CHECK_MONEY(G_context.s_out.amount);
                G_context.signing_ctx.flags = cmd->p2; // 1 when we want to return the CMU
                return add_s_output(&G_context.s_out, confirmation);
            }

        case ADD_O_ACTION:
            #ifdef ORCHARD
            if (cmd->p1 > 1 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != ORCHARD_OUT_LEN && cmd->lc != ORCHARD_OUT_LEN - 32)
                return io_send_sw(SW_WRONG_DATA_LENGTH);

            OVERRIDE_CONFIRMATION(cmd->p1);
            {
                memset(&G_context.o_action, 0, sizeof(o_action_t));
                p = cmd->data;

                MOVE_FIELD(G_context.o_action, nf);
                MOVE_FIELD(G_context.o_action, address);
                MOVE_FIELD(G_context.o_action, amount);
                MOVE_FIELD(G_context.o_action, epk);
                MOVE_FIELD(G_context.o_action, enc);
                if (cmd->lc == ORCHARD_OUT_LEN)
                    MOVE_FIELD(G_context.o_action, rseed);

                // in prod, rseed is picked by our PRNG, not the client's
                OVERRIDE_RSEED(G_context.o_action);

                // Check parameters
                CHECK_MONEY(G_context.o_action.amount);
                return add_o_action(&G_context.o_action, confirmation);
            }
            #else
                return io_send_sw(SW_INS_NOT_SUPPORTED);
            #endif

        case SET_S_NET:
            if (cmd->p1 > 1 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != sizeof(int64_t))
                return io_send_sw(SW_WRONG_DATA_LENGTH);

            p = cmd->data;
            int64_t net;
            memmove(&net, p, 8);
            CHECK_MONEY(net);
            return set_s_net(net);

        case SET_O_NET:
            if (cmd->p1 > 1 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != sizeof(int64_t))
                return io_send_sw(SW_WRONG_DATA_LENGTH);

            p = cmd->data;
            memmove(&net, p, 8);
            CHECK_MONEY(net);
            #ifdef ORCHARD
            return set_o_net(net);
            #else
            return io_send_sw(net != 0 ? SW_INS_NOT_SUPPORTED : SW_OK);
            #endif

        case SET_HEADER_DIGEST:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != 32)
                return io_send_sw(SW_WRONG_DATA_LENGTH);

            return set_header_digest(cmd->data);

        case SET_T_MERKLE_PROOF:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != 3 * 32)
                return io_send_sw(SW_WRONG_DATA_LENGTH);

            return set_t_merkle_proof((t_proofs_t *)cmd->data);

        case SET_S_MERKLE_PROOF:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != 3 * 32)
                return io_send_sw(SW_WRONG_DATA_LENGTH);

            return set_s_merkle_proof((s_proofs_t *)cmd->data);

        case SET_O_MERKLE_PROOF:
            #ifdef ORCHARD
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != 3 * 32)
                return io_send_sw(SW_WRONG_DATA_LENGTH);

            return set_o_merkle_proof((o_proofs_t *)cmd->data);
            #else
                return io_send_sw(SW_OK);
            #endif

        case CHANGE_STAGE:
            if (cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            return change_stage(cmd->p1);

        case CONFIRM_FEE:
            if (cmd->p2 > 1) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            OVERRIDE_CONFIRMATION(cmd->p1);

            G_context.signing_ctx.flags = cmd->p2;
            return confirm_fee(confirmation);

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
            memmove(G_context.txin_sig_digest, cmd->data, 32);
            return sign_transparent();

        case SIGN_SAPLING:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != 0 && cmd->lc != 64)
                return io_send_sw(SW_WRONG_DATA_LENGTH);
            memset(G_context.alpha, 0, 64);
            if (cmd->lc == 64)
                memmove(G_context.alpha, cmd->data, 64);
            // In prod, alpha is picked by our PRNG, not the client's
            OVERRIDE_ALPHA(G_context.alpha);

            return sign_sapling();

        case SIGN_ORCHARD:
            #ifdef ORCHARD
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != 0 && cmd->lc != 64)
                return io_send_sw(SW_WRONG_DATA_LENGTH);
            memset(G_context.alpha, 0, 64);
            if (cmd->lc == 64)
                memmove(G_context.alpha, cmd->data, 64);
            // In prod, alpha is picked by our PRNG, not the client's
            OVERRIDE_ALPHA(G_context.alpha);

            return sign_orchard();
            #else
                return io_send_sw(SW_INS_NOT_SUPPORTED);
            #endif

        case GET_S_SIGHASH:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != 0)
                return io_send_sw(SW_WRONG_DATA_LENGTH);

            return get_sighash(NULL);

        case END_TX:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != 0)
                return io_send_sw(SW_WRONG_DATA_LENGTH);
            reset_app();
            return io_send_sw(SW_OK);

#ifdef TEST
        case TEST_SAPLING_SIGN:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != 96)
                return io_send_sw(SW_WRONG_DATA_LENGTH);
            memmove(G_context.alpha, cmd->data, 64);
            sapling_sign(G_store.out_buffer, cmd->data + 64);
            return helper_send_response_bytes(G_store.out_buffer, 64);

        case GET_T_SIGHASH:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != 32)
                return io_send_sw(SW_WRONG_DATA_LENGTH);

            return get_sighash(cmd->data);

        case TEST_MATH:
            if (cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            return handler_test_math();

        case TEST_CMU:
            if (cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            return test_cmu(cmd->data);
#endif

        default:
            return io_send_sw(SW_INS_NOT_SUPPORTED);
    }
}
