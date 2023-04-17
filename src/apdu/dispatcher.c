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
#include "../crypto/key.h"
#include "../crypto/tx.h"
#include "../handler/get_version.h"
#include "../handler/get_app_name.h"
#include "../handler/get_fvk.h"
#include "../handler/get_address.h"
#include "../handler/test_math.h"
#include "../helper/send_response.h"

#include "../crypto/jubjub.h"
#include "../crypto/phash.h"
#include "../crypto/prf.h"

#define MOVE_FIELD(s,field) memmove(&s.field, p, sizeof(s.field)); p += sizeof(s.field);

int apdu_dispatcher(const command_t *cmd) {
    if (cmd->cla != CLA) {
        return io_send_sw(SW_CLA_NOT_SUPPORTED);
    }

    uint8_t *p;
    switch (cmd->ins) {
        case GET_VERSION:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            return handler_get_version();
        case GET_APP_NAME:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            return handler_get_app_name();
        
        case INITIALIZE:
            if (cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            crypto_derive_spending_key(cmd->p1);

            return helper_send_response_bytes(NULL, 0);

        case GET_FVK:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            return handler_get_fvk();
        
        case GET_ADDRESS:
            if (cmd->p1 > 1 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            return handler_get_address(cmd->p1 == 1);
        
        case INIT_TX:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != 32)
                return io_send_sw(SW_WRONG_DATA_LENGTH);

            return init_tx(cmd->data);

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
            if (cmd->lc != 8+1+20)
                return io_send_sw(SW_WRONG_DATA_LENGTH);

            {
                t_out_t t_out;
                memset(&t_out, 0, sizeof(t_out));
                p = cmd->data;

                MOVE_FIELD(t_out, amount);
                MOVE_FIELD(t_out, address_type);
                MOVE_FIELD(t_out, address_hash);

                return add_t_output(&t_out, cmd->p1 == 1);
            }

        case ADD_S_OUT:
            if (cmd->p1 > 1 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != 135)
                return io_send_sw(SW_WRONG_DATA_LENGTH);

            {
                s_out_t s_out;
                memset(&s_out, 0, 43+8+32+52);
                p = cmd->data;

                MOVE_FIELD(s_out, address);
                MOVE_FIELD(s_out, amount);
                MOVE_FIELD(s_out, epk);
                MOVE_FIELD(s_out, enc);

                return add_s_output(&s_out, cmd->p1 == 1);
            }

        case SET_S_NET:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != sizeof(int64_t))
                return io_send_sw(SW_WRONG_DATA_LENGTH);

            p = cmd->data;
            int64_t net;
            memmove(&net, p, 8);
            return set_sapling_net(&net);

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

        case CHANGE_STAGE:
            if (cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            return change_stage(cmd->p1);

        case GET_PROOFGEN_KEY:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            return get_proofgen_key();

        case SIGN_SAPLING:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != 0)
                return io_send_sw(SW_WRONG_DATA_LENGTH);

            return sign_sapling();

        case GET_SIGHASH:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != 0)
                return io_send_sw(SW_WRONG_DATA_LENGTH);

            return get_sighash();

        case GET_PUBKEY:
            if (cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != 0)
                return io_send_sw(SW_WRONG_DATA_LENGTH);

            uint8_t pk[33];
            derive_pubkey(pk, cmd->p1);

            return helper_send_response_bytes(pk, 33);

        case SIGN_TRANSPARENT:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != 32)
                return io_send_sw(SW_WRONG_DATA_LENGTH);
            return sign_transparent(cmd->data);

        case TEST_CMU: {
            uint8_t cmu[32];
            calc_cmu(cmu, cmd->data + 40, cmd->data + 8, (uint64_t *)cmd->data);
            return helper_send_response_bytes(cmu, 32);
        }

        case TEST_JUBJUB_HASH: {
            uint8_t gd_hash[32];
            jubjub_hash(gd_hash, cmd->data + 32, 11);
            extended_niels_point_t g_d_n;
            extn_from_bytes(&g_d_n, gd_hash);

            extended_point_t g_d;
            ext_set_identity(&g_d);
            ext_add(&g_d, &g_d_n);
            ext_to_bytes(gd_hash, &g_d);
            PRINTF("G_d: %.*H\n", 32, gd_hash);

            uint8_t rcm[64];
            memmove(rcm, cmd->data, 32);
            prf_expand_seed(rcm, 4);
            fr_from_wide(rcm);

            return helper_send_response_bytes(rcm, 32);
        }

        case TEST_PEDERSEN_HASH: {
            uint8_t cmu[32];
            pedersen_hash_cmu(cmu, (uint64_t *)cmd->data, cmd->data + 8, cmd->data + 40, (fr_t *)(cmd->data + 72));
            return helper_send_response_bytes(cmu, 32);
        }

        case TEST_MATH:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            return handler_test_math();
        default:
            return io_send_sw(SW_INS_NOT_SUPPORTED);
    }
}
