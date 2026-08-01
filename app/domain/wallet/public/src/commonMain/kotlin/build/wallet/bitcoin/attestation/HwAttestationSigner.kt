package build.wallet.bitcoin.attestation

import build.wallet.bitcoin.address.BitcoinAddress
import com.github.michaelbull.result.Result
import okio.ByteString

/**
 * Hardware spending-key signer seam for address attestation.
 * Firmware/NFC slice implements this; domain tests use a fake.
 */
fun interface HwAttestationSigner {
  suspend fun sign(
    digest: ByteString,
    path: SpendingChildPath,
    address: BitcoinAddress,
    message: AttestationMessage,
  ): Result<CompactEcdsaSignature, Error>
}
