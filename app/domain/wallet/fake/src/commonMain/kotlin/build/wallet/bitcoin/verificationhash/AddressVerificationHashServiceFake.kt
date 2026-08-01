package build.wallet.bitcoin.verificationhash

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.get
import com.github.michaelbull.result.getError
import okio.ByteString.Companion.toByteString

/**
 * Fake verification-hash service for UI tests. Builds a hash from the HW signer
 * result, or returns an injected [result] override.
 */
class AddressVerificationHashServiceFake(
  private val appSignature: CompactEcdsaSignature =
    CompactEcdsaSignature.createOrThrow(ByteArray(64) { 0x11 }.toByteString()),
  var result: Result<AddressVerificationHash, Error>? = null,
) : AddressVerificationHashService {
  var lastUsedSpk: UsedScriptPubKey? = null
  var lastMessage: VerificationMessage? = null
  var createCount: Int = 0

  override suspend fun create(
    usedSpk: UsedScriptPubKey,
    message: VerificationMessage,
    hwSigner: HwVerificationHashSigner,
  ): Result<AddressVerificationHash, Error> {
    createCount += 1
    lastUsedSpk = usedSpk
    lastMessage = message
    result?.let { return it }

    val challenge = AddressVerificationChallenge.create(
      network = usedSpk.network,
      address = usedSpk.address,
      scriptPubKey = usedSpk.scriptPubKey,
      path = usedSpk.path,
      message = message
    )
    val hwSignatureResult = hwSigner.sign(
      digest = challenge.digest,
      path = usedSpk.path,
      address = usedSpk.address,
      message = message
    )
    val hwSignature = hwSignatureResult.get()
      ?: return Err(hwSignatureResult.getError() ?: Error("HW verification hash sign failed"))
    return Ok(
      AddressVerificationHash(
        version = challenge.version,
        network = challenge.network,
        address = challenge.address,
        scriptPubKey = challenge.scriptPubKey,
        path = challenge.path,
        message = challenge.message,
        digest = challenge.digest,
        appSignature = appSignature,
        hwSignature = hwSignature
      )
    )
  }

  fun reset() {
    result = null
    lastUsedSpk = null
    lastMessage = null
    createCount = 0
  }
}
