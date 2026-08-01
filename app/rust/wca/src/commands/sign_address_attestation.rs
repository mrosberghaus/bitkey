use next_gen::generator;

use crate::{
    errors::CommandError,
    fwpb::{SignAddressAttestationCmd, Status},
    wca::decode_and_check,
};

use crate::command_interface::command;

#[derive(Debug, Clone)]
pub enum SignAddressAttestationResult {
    ConfirmationPending {
        response_handle: Vec<u8>,
        confirmation_handle: Vec<u8>,
    },
}

/// Confirmable command: firmware shows address + message, then signs the 32-byte digest
/// with the HW spending child. Result retrieved via `get_confirmation_result`.
#[generator(yield(Vec<u8>), resume(Vec<u8>))]
fn sign_address_attestation(
    digest: Vec<u8>,
    change: u32,
    address_index: u32,
    address: String,
    message: String,
) -> Result<SignAddressAttestationResult, CommandError> {
    let apdu: apdu::Command = SignAddressAttestationCmd {
        digest,
        change,
        address_index,
        address,
        message,
    }
    .try_into()?;

    let data = yield_!(apdu.into());
    let response = apdu::Response::from(data);
    let wallet_rsp = decode_and_check(response)?;

    if Status::try_from(wallet_rsp.status) == Ok(Status::ConfirmationPending) {
        return Ok(SignAddressAttestationResult::ConfirmationPending {
            response_handle: wallet_rsp.response_handle,
            confirmation_handle: wallet_rsp.confirmation_handle,
        });
    }

    Err(CommandError::InvalidResponse)
}

command!(SignAddressAttestation = sign_address_attestation -> SignAddressAttestationResult,
    digest: Vec<u8>,
    change: u32,
    address_index: u32,
    address: String,
    message: String
);

#[cfg(test)]
mod tests {
    use prost::Message;

    use crate::{
        command_interface::{Command, State},
        errors::CommandError,
        fwpb::{Status, WalletRsp},
    };

    use super::{SignAddressAttestation, SignAddressAttestationResult};

    fn make_response(wallet_rsp: WalletRsp) -> Vec<u8> {
        let mut buf = wallet_rsp.encode_to_vec();
        buf.extend_from_slice(&[0x90, 0x00]);
        buf
    }

    #[test]
    fn confirmation_pending() -> Result<(), CommandError> {
        let command = SignAddressAttestation::new(
            vec![0x11; 32],
            0,
            1,
            "tb1qtest".to_string(),
            "hello".to_string(),
        );
        command.next(Vec::default())?;

        let response_handle = vec![0x01, 0x02, 0x03, 0x04];
        let confirmation_handle = vec![0x05, 0x06, 0x07, 0x08];

        let response = make_response(WalletRsp {
            status: Status::ConfirmationPending.into(),
            response_handle: response_handle.clone(),
            confirmation_handle: confirmation_handle.clone(),
            msg: None,
            ..Default::default()
        });

        match command.next(response) {
            Ok(State::Result {
                value:
                    SignAddressAttestationResult::ConfirmationPending {
                        response_handle: rh,
                        confirmation_handle: ch,
                    },
            }) => {
                assert_eq!(rh, response_handle);
                assert_eq!(ch, confirmation_handle);
            }
            other => panic!("Expected ConfirmationPending, got {:?}", other),
        }

        Ok(())
    }
}
