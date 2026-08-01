package build.wallet.bitcoin.verificationhash

sealed class AddressVerificationHashResult {
  data object Valid : AddressVerificationHashResult()

  data class Invalid(val reasons: List<AddressVerificationHashInvalidReason>) :
    AddressVerificationHashResult()
}

enum class AddressVerificationHashInvalidReason {
  DigestMismatch,
  AddressMismatch,
  ScriptPubKeyMismatch,
  MissingAppPublicKey,
  MissingHwPublicKey,
  InvalidAppSignature,
  InvalidHwSignature,
}
