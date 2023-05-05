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

#ifdef HAVE_BAGL

#pragma GCC diagnostic ignored "-Wformat-invalid-specifier"  // snprintf
#pragma GCC diagnostic ignored "-Wformat-extra-args"         // snprintf

#include <stdbool.h>  // bool
#include <string.h>   // memset

#include "os.h"
#include "ux.h"
#include "glyphs.h"

#include "display.h"
#include "constants.h"
#include "../globals.h"
#include "../io.h"
#include "../sw.h"
#include "action/validate.h"
#include "../common/format.h"
#include "../helper/formatters.h"
#include "menu.h"

static action_validate_cb g_validate_callback;

static void ui_action_validate_address(bool choice) {
    validate_address(choice);
    ui_menu_main();
}

char processing_msg[20];

// Step with icon and text
UX_STEP_NOCB(ux_show_processing_step, pnn, {&C_icon_processing, "Processing", processing_msg});
// Step with icon and text
UX_STEP_NOCB(ux_display_confirm_addr_step, pn, {&C_icon_eye, "Confirm Address"});
// Step with title/text for address
UX_STEP_NOCB(ux_display_address_step,
             bnnn_paging,
             {
                 .title = "Address",
                 .text = G_context.address,
             });
UX_STEP_NOCB(ux_display_amount_step,
             bnnn_paging,
             {
                 .title = "Amount",
                 .text = G_context.amount,
             });
UX_STEP_NOCB(ux_display_fee_step,
             bnnn_paging,
             {
                 .title = "Fee",
                 .text = G_context.amount,
             });
// Step with approve button
UX_STEP_CB(ux_display_approve_step,
           pb,
           (*g_validate_callback)(true),
           {
               &C_icon_validate_14,
               "Approve",
           });
// Step with reject button
UX_STEP_CB(ux_display_reject_step,
           pb,
           (*g_validate_callback)(false),
           {
               &C_icon_crossmark,
               "Reject",
           });

UX_FLOW(ux_processing_flow,
        &ux_show_processing_step);

int ui_display_processing(const char *msg) {
    strlcpy(processing_msg, msg, 20);
    ux_flow_init(0, ux_processing_flow, NULL);
    return 0;
}

// FLOW to display address:
// #1 screen: eye icon + "Confirm Address"
// #2 screen: display address
// #3 screen: approve button
// #4 screen: reject button
UX_FLOW(ux_display_address_flow,
        &ux_display_confirm_addr_step,
        &ux_display_address_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

int ui_display_address() {
    g_validate_callback = &ui_action_validate_address;

    ux_flow_init(0, ux_display_address_flow, NULL);
    return 0;
}

UX_FLOW(ux_confirm_out_flow,
        &ux_display_address_step,
        &ux_display_amount_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

UX_FLOW(ux_confirm_fee_flow,
        &ux_display_fee_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

int ui_confirm_t_out(t_out_t *t_out) {
    g_validate_callback = &validate_out;

    format_t_address(t_out->address_hash);
    format_amount(t_out->amount);

    ux_flow_init(0, ux_confirm_out_flow, NULL);
    return 0;
}

int ui_confirm_s_out(s_out_t *s_out) {
    g_validate_callback = &validate_out;

    format_s_address(s_out->address);
    format_amount(s_out->amount);

    ux_flow_init(0, ux_confirm_out_flow, NULL);
    return 0;
}

int ui_confirm_o_out(o_action_t *action) {
    g_validate_callback = &validate_out;

    format_u_address(action->address);
    format_amount(action->amount);

    ux_flow_init(0, ux_confirm_out_flow, NULL);
    return 0;
}

int ui_confirm_fee(int64_t fee) {
    g_validate_callback = &validate_fee;

    format_amount(fee);

    ux_flow_init(0, ux_confirm_fee_flow, NULL);
    return 0;
}

#endif
