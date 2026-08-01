#pragma once

#include "rtos.h"

// W3 confirmable BIP-322: display address + message, then sign sighash
// with HW spending child at change/index.
void bip322_sighash_handle_init(ipc_ref_t* message);
void bip322_sighash_register_handlers(void);
void bip322_sighash_clear_session(void);
