package build.wallet.bitcoin.attestation

import build.wallet.bitcoin.address.BitcoinAddress
import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Result
import okio.ByteString

/**
 * Production placeholder until NFC `signAddressAttestation` is wired.
 *
 * TODO(address-attestation-nfc): replace with [NfcHwAttestationSigner] that
 * runs an NFC session and calls firmware once the command exists.
 */
@BitkeyInject(AppScope::class)
class HwAttestationSignerUnsupported : HwAttestationSigner {
  override suspend fun sign(
    digest: ByteString,
    path: SpendingChildPath,
    address: BitcoinAddress,
    message: AttestationMessage,
  ): Result<CompactEcdsaSignature, Error> =
    Err(
      Error(
        "HwAttestationSigner is not wired; NFC signAddressAttestation is not implemented yet"
      )
    )
}
