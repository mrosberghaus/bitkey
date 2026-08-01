package build.wallet.bitcoin.bip322

import build.wallet.bitcoin.address.BitcoinAddress
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import okio.ByteString.Companion.toByteString

/**
 * Deterministic fake HW signer for domain tests.
 * Returns a fixed 64-byte compact signature; does not verify against real keys.
 */
class HwBip322SighashSignerFake(
  private val signature: CompactEcdsaSignature =
    CompactEcdsaSignature.createOrThrow(ByteArray(64) { 0x42 }.toByteString()),
) : HwBip322SighashSigner {
  var lastSighash: Bip322Sighash? = null
  var lastPath: SpendingChildPath? = null
  var lastAddress: BitcoinAddress? = null
  var lastMessage: ProveAddressMessage? = null
  var signCount: Int = 0

  override suspend fun sign(
    sighash: Bip322Sighash,
    path: SpendingChildPath,
    address: BitcoinAddress,
    message: ProveAddressMessage,
  ): Result<CompactEcdsaSignature, Error> {
    signCount += 1
    lastSighash = sighash
    lastPath = path
    lastAddress = address
    lastMessage = message
    return Ok(signature)
  }
}
