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

#include <stdint.h>  // uint*_t
#include <string.h>  // memset, explicit_bzero

#include "os.h"
#include "ux.h"

#include "types.h"
#include "globals.h"
#include "io.h"
#include "sw.h"
#include "ui/menu.h"
#include "apdu/parser.h"
#include "apdu/dispatcher.h"

uint8_t G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];
ux_state_t G_ux;
bolos_ux_params_t G_ux_params;
global_ctx_t G_context;
temp_t G_store;


#ifdef CHECK_STACK
// This symbol is defined by the link script to be at the start of the stack
// area.
extern unsigned long _stack;
#define STACK_CANARY (*((volatile uint32_t*) &_stack))

void init_canary() {
    STACK_CANARY = 0xDEADBEEF;
}

void check_canary_inner() {
    if (STACK_CANARY != 0xDEADBEEF)
        THROW(EXCEPTION_OVERFLOW);
    PRINTF("stack checked\n");
}
int canary_depth_inner(void *p) { 
    return (uint8_t *)p - (uint8_t *)(&_stack);
}
uint32_t get_canary() { return STACK_CANARY; }
#else
void init_canary() {}
void check_canary_inner() {}
uint32_t get_canary() { return 0; }
#endif

/**
 * Handle APDU command received and send back APDU response using handlers.
 */
void app_main() {
    init_canary();
    // Length of APDU command received in G_io_apdu_buffer
    int input_len = 0;
    // Structured APDU command
    command_t cmd;

    io_init();

    // Reset context
    explicit_bzero(&G_context, sizeof(G_context));
    G_context.account = 0xFF;

    for (;;) {
        BEGIN_TRY {
            TRY {
                // Reset structured APDU command
                memset(&cmd, 0, sizeof(cmd));

                // Receive command bytes in G_io_apdu_buffer
                if ((input_len = io_recv_command()) < 0) {
                    CLOSE_TRY;
                    return;
                }

                // Parse APDU command from G_io_apdu_buffer
                if (!apdu_parser(&cmd, G_io_apdu_buffer, input_len)) {
                    PRINTF("=> /!\\ BAD LENGTH: %.*H\n", input_len, G_io_apdu_buffer);
                    io_send_sw(SW_WRONG_DATA_LENGTH);
                    CLOSE_TRY;
                    continue;
                }

                PRINTF("=> CLA=%02X | INS=%02X | P1=%02X | P2=%02X | Lc=%02X | CData=%.*H\n",
                       cmd.cla,
                       cmd.ins,
                       cmd.p1,
                       cmd.p2,
                       cmd.lc,
                       cmd.lc,
                       cmd.data);

                // Dispatch structured APDU command to handler
                if (apdu_dispatcher(&cmd) < 0) {
                    CLOSE_TRY;
                    return;
                }
            }
            CATCH(EXCEPTION_IO_RESET) {
                THROW(EXCEPTION_IO_RESET);
            }
            CATCH_OTHER(e) {
                io_send_sw(e);
                cx_bn_unlock();
            }
            FINALLY {
                check_canary();
            }
            END_TRY;
        }
    }
}

/**
 * Exit the application and go back to the dashboard.
 */
void app_exit() {
    BEGIN_TRY_L(exit) {
        TRY_L(exit) {
            os_sched_exit(-1);
        }
        FINALLY_L(exit) {
        }
    }
    END_TRY_L(exit);
}

/**
 * Main loop to setup USB, Bluetooth, UI and launch app_main().
 */
__attribute__((section(".boot"))) int main() {
    __asm volatile("cpsie i");

    os_boot();

    for (;;) {
        // Initialize the UX system
        UX_INIT();

        BEGIN_TRY {
            TRY {
                io_seproxyhal_init();

#ifdef HAVE_BLE
                G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
#endif  // HAVE_BLE
                USB_power(0);
                USB_power(1);

                ui_menu_main();

#ifdef HAVE_BLE
                BLE_power(0, NULL);
                BLE_power(1, NULL);
#endif  // HAVE_BLE
                app_main();
            }
            CATCH(EXCEPTION_IO_RESET) {
                CLOSE_TRY;
                continue;
            }
            CATCH_ALL {
                CLOSE_TRY;
                break;
            }
            FINALLY {
            }
        }
        END_TRY;
    }

    app_exit();

    return 0;
}
