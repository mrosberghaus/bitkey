package build.wallet.bitcoin.bip322

import build.wallet.bitcoin.verificationhash.UsedScriptPubKey
import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.coroutineBinding

@BitkeyInject(AppScope::class)
class ProveAddressServiceImpl(
  private val appSigner: AppBip322SighashSigner,
  private val scriptResolver: SortedMultiScriptResolver,
) : ProveAddressService {
  override suspend fun prove(
    usedSpk: UsedScriptPubKey,
    message: ProveAddressMessage,
    hwSigner: HwBip322SighashSigner,
  ): Result<Bip322SimpleProof, Error> =
    coroutineBinding {
      val script = scriptResolver
        .resolve(path = usedSpk.path, expectedScriptPubKey = usedSpk.scriptPubKey)
        .bind()

      val challenge = Bip322Challenge.create(
        usedSpk = usedSpk,
        message = message,
        script = script
      ).bind()

      val appCompact = appSigner
        .sign(sighash = challenge.sighash, path = usedSpk.path)
        .bind()

      val hwCompact = hwSigner
        .sign(
          sighash = challenge.sighash,
          path = usedSpk.path,
          address = usedSpk.address,
          message = message
        )
        .bind()

      val witness = SortedMultiWitness.assemble(
        script = script,
        appSig = WitnessEcdsaSignature.fromCompact(appCompact.bytes),
        hwSig = WitnessEcdsaSignature.fromCompact(hwCompact.bytes)
      )

      Bip322SimpleProof(
        address = usedSpk.address,
        message = message,
        witness = witness
      )
    }
}
