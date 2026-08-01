package build.wallet.bitcoin.attestation

import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.coroutineBinding

@BitkeyInject(AppScope::class)
class AddressAttestationServiceImpl(
  private val appSpendingDigestSigner: AppSpendingDigestSigner,
) : AddressAttestationService {
  override suspend fun attest(
    usedSpk: UsedScriptPubKey,
    message: AttestationMessage,
    hwSigner: HwAttestationSigner,
  ): Result<AddressAttestation, Error> =
    coroutineBinding {
      val challenge = AddressAttestationChallenge.create(
        network = usedSpk.network,
        address = usedSpk.address,
        scriptPubKey = usedSpk.scriptPubKey,
        path = usedSpk.path,
        message = message
      )

      val appSignature = appSpendingDigestSigner
        .signDigest(digest = challenge.digest, path = usedSpk.path)
        .bind()

      val hwSignature = hwSigner
        .sign(
          digest = challenge.digest,
          path = usedSpk.path,
          address = usedSpk.address,
          message = message
        )
        .bind()

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
    }
}
