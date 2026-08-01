#include "address_verification_hash_impl.h"

#include "attributes.h"
#include "bip32.h"
#include "confirmation_manager.h"
#include "display.pb.h"
#include "ecc.h"
#include "ew.h"
#include "hash.h"
#include "key_manager_task_impl.h"
#include "log.h"
#include "proto_helpers.h"
#include "secutils.h"
#include "ui_messaging.h"
#include "wallet.h"
#include "wallet.pb.h"
#include "wallet_address.h"

#include <string.h>

#define HARDENED_BIT       (0x80000000u)
#define BIP84_PURPOSE      (84u | HARDENED_BIT)
#define BIP84_COIN_MAINNET (0u | HARDENED_BIT)
#define BIP84_COIN_TESTNET (1u | HARDENED_BIT)
#define MAX_WITNESS_PROGRAM_SIZE (34)

typedef struct {
  uint8_t digest[SHA256_DIGEST_SIZE];
  uint32_t change;
  uint32_t address_index;
  char address[128];
  char message[281];
  bool valid;
  bool sign_attempted;
  bool signed_ok;
  fwpb_status sign_result;
  uint8_t signature[ECC_SIG_SIZE];
} address_verification_hash_session_t;

static SHARED_TASK_BSS address_verification_hash_session_t aa_session = {0};

static void aa_session_clear(void) {
  memzero(&aa_session, sizeof(aa_session));
}

void address_verification_hash_clear_session(void) {
  confirmation_manager_clear();
  aa_session_clear();
}

static bool aa_derive_and_check_address(const wallet_keyset_t* keyset, char* derived_out,
                                        size_t derived_len) {
  if (aa_session.change > 1u || aa_session.address_index >= HARDENED_BIT) {
    return false;
  }

  const uint32_t expected_coin =
    (keyset->network == NETWORK_MAINNET) ? BIP84_COIN_MAINNET : BIP84_COIN_TESTNET;
  uint32_t derivation_path[] = {
    BIP84_PURPOSE,
    expected_coin,
    ((uint32_t)keyset->account_index) | HARDENED_BIT,
    aa_session.change,
    aa_session.address_index,
  };

  uint8_t scriptpubkey[MAX_WITNESS_PROGRAM_SIZE] = {0};
  size_t scriptpubkey_len = 0;
  if (wallet_derive_p2wsh_scriptpubkey(keyset, derivation_path,
                                       sizeof(derivation_path) / sizeof(derivation_path[0]),
                                       scriptpubkey, sizeof(scriptpubkey),
                                       &scriptpubkey_len) != WALLET_RES_OK) {
    return false;
  }

  ew_network_t network =
    (keyset->network == NETWORK_MAINNET) ? EW_NETWORK_MAINNET : EW_NETWORK_TESTNET;
  if (ew_script_to_address(scriptpubkey, scriptpubkey_len, network, derived_out, derived_len) !=
      EW_OK) {
    return false;
  }
  return true;
}

static void aa_sign(void) {
  aa_session.sign_attempted = true;

  wallet_keyset_t keyset = {0};
  if (!wkek_read_and_decrypt(WALLET_KEYSET_PATH, (uint8_t*)&keyset, sizeof(keyset))) {
    LOGE("AA: keyset load");
    aa_session.sign_result = fwpb_status_DESCRIPTOR_NOT_LOADED;
    return;
  }
  if (keyset.version != WALLET_KEYSET_VERSION) {
    LOGE("AA: keyset ver");
    memzero(&keyset, sizeof(keyset));
    aa_session.sign_result = fwpb_status_ERROR;
    return;
  }

  char derived[128] = {0};
  if (!aa_derive_and_check_address(&keyset, derived, sizeof(derived))) {
    LOGE("AA: derive address failed");
    memzero(&keyset, sizeof(keyset));
    aa_session.sign_result = fwpb_status_ERROR;
    return;
  }
  if (strncmp(derived, aa_session.address, sizeof(aa_session.address)) != 0) {
    LOGE("AA: address bind mismatch");
    memzero(&keyset, sizeof(keyset));
    aa_session.sign_result = fwpb_status_INVALID_ARGUMENT;
    return;
  }

  const uint32_t expected_coin =
    (keyset.network == NETWORK_MAINNET) ? BIP84_COIN_MAINNET : BIP84_COIN_TESTNET;
  uint32_t path_indices[] = {
    BIP84_PURPOSE,
    expected_coin,
    ((uint32_t)keyset.account_index) | HARDENED_BIT,
    aa_session.change,
    aa_session.address_index,
  };
  derivation_path_t path = {
    .indices = path_indices,
    .num_indices = sizeof(path_indices) / sizeof(path_indices[0]),
  };

  key_manager_sign_result_t sign_res =
    key_manager_derive_and_sign(path, aa_session.digest, aa_session.signature);
  memzero(&keyset, sizeof(keyset));

  switch (sign_res) {
    case KEY_MANAGER_SIGN_SUCCESS:
      aa_session.signed_ok = true;
      aa_session.sign_result = fwpb_status_SUCCESS;
      break;
    case KEY_MANAGER_SIGN_DERIVATION_FAILED:
      aa_session.sign_result = fwpb_status_KEY_DERIVATION_FAILED;
      break;
    case KEY_MANAGER_SIGN_POLICY_VIOLATION:
      aa_session.sign_result = fwpb_status_INVALID_ARGUMENT;
      break;
    default:
      aa_session.sign_result = fwpb_status_SIGNING_FAILED;
      break;
  }
}

void address_verification_hash_handle_init(ipc_ref_t* message) {
  fwpb_wallet_cmd* cmd = proto_get_cmd((uint8_t*)message->object, message->length);
  fwpb_wallet_rsp* rsp = proto_get_rsp();
  rsp->status = fwpb_status_ERROR;

  address_verification_hash_clear_session();

  fwpb_sign_address_verification_hash_cmd* acmd = &cmd->msg.sign_address_verification_hash_cmd;
  if (acmd->digest.size != SHA256_DIGEST_SIZE) {
    LOGE("AA: bad digest size");
    rsp->status = fwpb_status_INVALID_ARGUMENT;
    goto out;
  }
  if (acmd->change > 1u) {
    LOGE("AA: bad change");
    rsp->status = fwpb_status_INVALID_ARGUMENT;
    goto out;
  }
  if (acmd->address[0] == '\0' || acmd->message[0] == '\0') {
    LOGE("AA: empty address/message");
    rsp->status = fwpb_status_INVALID_ARGUMENT;
    goto out;
  }

  wallet_keyset_t keyset = {0};
  if (!wkek_read_and_decrypt(WALLET_KEYSET_PATH, (uint8_t*)&keyset, sizeof(keyset))) {
    LOGE("AA: keyset load");
    rsp->status = fwpb_status_DESCRIPTOR_NOT_LOADED;
    goto out;
  }
  if (keyset.version != WALLET_KEYSET_VERSION) {
    LOGE("AA: keyset ver");
    memzero(&keyset, sizeof(keyset));
    rsp->status = fwpb_status_ERROR;
    goto out;
  }

  memcpy(aa_session.digest, acmd->digest.bytes, SHA256_DIGEST_SIZE);
  aa_session.change = acmd->change;
  aa_session.address_index = acmd->address_index;
  strncpy(aa_session.address, acmd->address, sizeof(aa_session.address) - 1);
  strncpy(aa_session.message, acmd->message, sizeof(aa_session.message) - 1);

  char derived[128] = {0};
  if (!aa_derive_and_check_address(&keyset, derived, sizeof(derived))) {
    LOGE("AA: precheck derive failed");
    memzero(&keyset, sizeof(keyset));
    rsp->status = fwpb_status_ERROR;
    goto out;
  }
  memzero(&keyset, sizeof(keyset));
  if (strncmp(derived, aa_session.address, sizeof(aa_session.address)) != 0) {
    LOGE("AA: precheck address mismatch");
    aa_session_clear();
    rsp->status = fwpb_status_INVALID_ARGUMENT;
    goto out;
  }

  aa_session.valid = true;

  uint8_t response_handle[CONFIRMATION_HANDLE_SIZE];
  uint8_t confirmation_handle[CONFIRMATION_HANDLE_SIZE];
  uint8_t token = 1;
  if (confirmation_manager_create(CONFIRMATION_TYPE_SIGN_ADDRESS_VERIFICATION_HASH, &token, sizeof(token),
                                  response_handle, sizeof(response_handle), confirmation_handle,
                                  sizeof(confirmation_handle)) != CONFIRMATION_RESULT_SUCCESS) {
    LOGE("AA: CM create failed");
    aa_session_clear();
    goto out;
  }

  fwpb_display_params_privileged_action display_params = {0};
  strncpy(display_params.title, "Prove address", sizeof(display_params.title) - 1);
  display_params.which_action =
    fwpb_display_params_privileged_action_confirm_address_verification_hash_tag;
  strncpy(display_params.action.confirm_address_verification_hash.address, aa_session.address,
          sizeof(display_params.action.confirm_address_verification_hash.address) - 1);
  strncpy(display_params.action.confirm_address_verification_hash.message, aa_session.message,
          sizeof(display_params.action.confirm_address_verification_hash.message) - 1);
  UI_SHOW_EVENT_WITH_DATA(UI_EVENT_START_PRIVILEGED_ACTION, &display_params,
                          sizeof(display_params));

  rsp->status = fwpb_status_CONFIRMATION_PENDING;
  memcpy(rsp->response_handle.bytes, response_handle, sizeof(response_handle));
  rsp->response_handle.size = sizeof(response_handle);
  memcpy(rsp->confirmation_handle.bytes, confirmation_handle, sizeof(confirmation_handle));
  rsp->confirmation_handle.size = sizeof(confirmation_handle);

out:
  proto_send_rsp(cmd, rsp);
}

static bool aa_confirmation_result_handler(ipc_ref_t* message) {
  fwpb_wallet_cmd* cmd = proto_get_cmd((uint8_t*)message->object, message->length);
  fwpb_wallet_rsp* rsp = proto_get_rsp();

  rsp->which_msg = fwpb_wallet_rsp_get_confirmation_result_rsp_tag;

  confirmation_result_t validation =
    confirmation_manager_validate(cmd->msg.get_confirmation_result_cmd.response_handle.bytes,
                                  cmd->msg.get_confirmation_result_cmd.response_handle.size,
                                  cmd->msg.get_confirmation_result_cmd.confirmation_handle.bytes,
                                  cmd->msg.get_confirmation_result_cmd.confirmation_handle.size);

  if (validation == CONFIRMATION_RESULT_NOT_APPROVED) {
    rsp->status = fwpb_status_CONFIRMATION_PENDING;
    proto_send_rsp(cmd, rsp);
    return true;
  }

  if (validation != CONFIRMATION_RESULT_SUCCESS) {
    rsp->status = fwpb_status_CONFIRMATION_NOT_COMPLETED;
    LOGE("AA: confirm fail: %d", validation);
    address_verification_hash_clear_session();
    proto_send_rsp(cmd, rsp);
    return false;
  }

  if (!aa_session.sign_attempted) {
    aa_sign();
  }

  if (aa_session.signed_ok) {
    rsp->msg.get_confirmation_result_rsp.which_result =
      fwpb_get_confirmation_result_rsp_sign_address_verification_hash_result_tag;
    memcpy(rsp->msg.get_confirmation_result_rsp.result.sign_address_verification_hash_result.signature
             .bytes,
           aa_session.signature, ECC_SIG_SIZE);
    rsp->msg.get_confirmation_result_rsp.result.sign_address_verification_hash_result.signature.size =
      ECC_SIG_SIZE;
    rsp->status = fwpb_status_SUCCESS;
    address_verification_hash_clear_session();
    ui_show_confirmation("Success", false);
    proto_send_rsp(cmd, rsp);
    return true;
  }

  if (aa_session.sign_attempted) {
    rsp->status = aa_session.sign_result;
    address_verification_hash_clear_session();
    proto_send_rsp(cmd, rsp);
    return false;
  }

  rsp->status = fwpb_status_CONFIRMATION_PENDING;
  proto_send_rsp(cmd, rsp);
  return true;
}

void address_verification_hash_register_handlers(void) {
  confirmation_manager_register_result_handler(CONFIRMATION_TYPE_SIGN_ADDRESS_VERIFICATION_HASH,
                                               aa_confirmation_result_handler);
}
