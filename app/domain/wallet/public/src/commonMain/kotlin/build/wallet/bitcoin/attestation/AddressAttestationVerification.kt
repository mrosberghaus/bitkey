package build.wallet.bitcoin.attestation

sealed class AddressAttestationVerification {
  data object Valid : AddressAttestationVerification()

  data class Invalid(val reasons: List<AddressAttestationInvalidReason>) :
    AddressAttestationVerification()
}

enum class AddressAttestationInvalidReason {
  DigestMismatch,
  AddressMismatch,
  ScriptPubKeyMismatch,
  MissingAppPublicKey,
  MissingHwPublicKey,
  InvalidAppSignature,
  InvalidHwSignature,
}
