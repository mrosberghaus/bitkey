#pragma once

#include "rtos.h"

// W3 confirmable address attestation: display address + message, then sign digest
// with HW spending child at change/index.
void address_attestation_handle_init(ipc_ref_t* message);
void address_attestation_register_handlers(void);
void address_attestation_clear_session(void);
