package build.wallet.bitcoin.bip322

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.get
import com.github.michaelbull.result.getError
import okio.ByteString
import okio.ByteString.Companion.toByteString

/**
 * Fake prove-address service for UI tests. Builds an [smp] export from the HW signer
 * result, or returns an injected [result] override.
 */
class ProveAddressServiceFake(
  var result: Result<Bip322SimpleProof, Error>? = null,
) : ProveAddressService {
  var lastUsedSpk: UsedScriptPubKey? = null
  var lastMessage: ProveAddressMessage? = null
  var proveCount: Int = 0

  override suspend fun prove(
    usedSpk: UsedScriptPubKey,
    message: ProveAddressMessage,
    hwSigner: HwBip322SighashSigner,
  ): Result<Bip322SimpleProof, Error> {
    proveCount += 1
    lastUsedSpk = usedSpk
    lastMessage = message
    result?.let { return it }

    val sighash = Bip322Sighash.of(ByteArray(32) { 0x11 }.toByteString())
    val hwSignatureResult = hwSigner.sign(
      sighash = sighash,
      path = usedSpk.path,
      address = usedSpk.address,
      message = message
    )
    val hwSignature = hwSignatureResult.get()
      ?: return Err(hwSignatureResult.getError() ?: Error("HW BIP-322 sighash sign failed"))

    val stack = listOf(
      ByteString.EMPTY,
      ByteArray(72) { 0x11 }.toByteString(),
      hwSignature.bytes,
      ByteString.EMPTY,
      ByteArray(8) { 0x22 }.toByteString()
    )
    return Ok(
      Bip322SimpleProof(
        address = usedSpk.address,
        message = message,
        witness = SortedMultiWitness(stack)
      )
    )
  }

  fun reset() {
    result = null
    lastUsedSpk = null
    lastMessage = null
    proveCount = 0
  }
}
