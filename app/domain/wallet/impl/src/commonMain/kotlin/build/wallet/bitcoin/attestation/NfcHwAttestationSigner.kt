package build.wallet.bitcoin.attestation

import build.wallet.bitcoin.address.BitcoinAddress
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Result
import okio.ByteString

/**
 * NFC seam for address attestation. Not DI-bound yet.
 *
 * TODO(address-attestation-nfc): add `signAddressAttestation` on NfcCommands
 * (FeatureNotSupported stubs OK), wire an NFC session, replace
 * [HwAttestationSignerUnsupported] with this.
 */
class NfcHwAttestationSigner : HwAttestationSigner {
  override suspend fun sign(
    digest: ByteString,
    path: SpendingChildPath,
    address: BitcoinAddress,
    message: AttestationMessage,
  ): Result<CompactEcdsaSignature, Error> =
    Err(
      Error(
        "NfcHwAttestationSigner stub: wire signAddressAttestation NFC command before use"
      )
    )
}
