#pragma once

#include "rtos.h"

// W3 confirmable verification hash: display address + message, then sign digest
// with HW spending child at change/index.
void address_verification_hash_handle_init(ipc_ref_t* message);
void address_verification_hash_register_handlers(void);
void address_verification_hash_clear_session(void);
