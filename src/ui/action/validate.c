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

#include <stdbool.h>  // bool

#include "validate.h"
#include "../menu.h"
#include "../../sw.h"
#include "../../globals.h"
#include "../../helper/send_response.h"

void validate_address(bool choice) {
    if (choice) {
        helper_send_response_bytes(NULL, 0);
    } else {
        reset_app();
        io_send_sw(SW_DENY);
    }
}

void validate_out(bool choice) {
    if (choice) {
        ui_menu_main();
        helper_send_response_bytes(NULL, 0);
    } else {
        reset_app();
        io_send_sw(SW_DENY);
    }
}

void validate_fee(bool choice) {
    if (choice) {
        G_context.signing_ctx.stage = SIGN; // last confirmation approved - ok to sign
        helper_send_response_bytes(NULL, 0);
    } else {
        reset_app();
        io_send_sw(SW_DENY);
    }
}

void reset_app() {
    G_context.signing_ctx.stage = IDLE;
    ui_menu_main();
}
