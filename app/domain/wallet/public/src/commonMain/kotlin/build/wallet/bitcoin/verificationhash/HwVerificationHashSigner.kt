package build.wallet.bitcoin.verificationhash

import build.wallet.bitcoin.address.BitcoinAddress
import com.github.michaelbull.result.Result
import okio.ByteString

/**
 * Hardware spending-key signer seam for verification hash.
 * Firmware/NFC slice implements this; domain tests use a fake.
 */
fun interface HwVerificationHashSigner {
  suspend fun sign(
    digest: ByteString,
    path: SpendingChildPath,
    address: BitcoinAddress,
    message: VerificationMessage,
  ): Result<CompactEcdsaSignature, Error>
}
