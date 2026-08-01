package build.wallet.bitcoin.attestation

import com.github.michaelbull.result.Result

interface AddressAttestationService {
  /**
   * App-sign + HW-sign a used scriptPubKey for [message], returning a verifiable attestation.
   */
  suspend fun attest(
    usedSpk: UsedScriptPubKey,
    message: AttestationMessage,
    hwSigner: HwAttestationSigner,
  ): Result<AddressAttestation, Error>
}
