package build.wallet.bitcoin.attestation

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.get
import com.github.michaelbull.result.getError
import okio.ByteString.Companion.toByteString

/**
 * Fake attestation service for UI tests. Builds an attestation from the HW signer
 * result, or returns an injected [result] override.
 */
class AddressAttestationServiceFake(
  private val appSignature: CompactEcdsaSignature =
    CompactEcdsaSignature.createOrThrow(ByteArray(64) { 0x11 }.toByteString()),
  var result: Result<AddressAttestation, Error>? = null,
) : AddressAttestationService {
  var lastUsedSpk: UsedScriptPubKey? = null
  var lastMessage: AttestationMessage? = null
  var attestCount: Int = 0

  override suspend fun attest(
    usedSpk: UsedScriptPubKey,
    message: AttestationMessage,
    hwSigner: HwAttestationSigner,
  ): Result<AddressAttestation, Error> {
    attestCount += 1
    lastUsedSpk = usedSpk
    lastMessage = message
    result?.let { return it }

    val challenge = AddressAttestationChallenge.create(
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
      ?: return Err(hwSignatureResult.getError() ?: Error("HW attestation sign failed"))
    return Ok(
      AddressAttestation(
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
    attestCount = 0
  }
}
