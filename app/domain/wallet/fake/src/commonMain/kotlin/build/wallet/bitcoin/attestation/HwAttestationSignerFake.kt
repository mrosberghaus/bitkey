package build.wallet.bitcoin.attestation

import build.wallet.bitcoin.address.BitcoinAddress
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import okio.ByteString
import okio.ByteString.Companion.toByteString

/**
 * Deterministic fake HW signer for UI/domain tests.
 * Returns a fixed 64-byte compact signature; does not verify against real keys.
 */
class HwAttestationSignerFake(
  private val signature: CompactEcdsaSignature =
    CompactEcdsaSignature.createOrThrow(ByteArray(64) { 0x42 }.toByteString()),
) : HwAttestationSigner {
  var lastDigest: ByteString? = null
  var lastPath: SpendingChildPath? = null
  var lastAddress: BitcoinAddress? = null
  var lastMessage: AttestationMessage? = null
  var signCount: Int = 0

  override suspend fun sign(
    digest: ByteString,
    path: SpendingChildPath,
    address: BitcoinAddress,
    message: AttestationMessage,
  ): Result<CompactEcdsaSignature, Error> {
    signCount += 1
    lastDigest = digest
    lastPath = path
    lastAddress = address
    lastMessage = message
    return Ok(signature)
  }
}
