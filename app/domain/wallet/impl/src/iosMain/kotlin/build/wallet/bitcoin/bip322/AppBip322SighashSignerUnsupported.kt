package build.wallet.bitcoin.bip322

import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Result

@BitkeyInject(AppScope::class)
class AppBip322SighashSignerUnsupported : AppBip322SighashSigner {
  override suspend fun sign(
    sighash: Bip322Sighash,
    path: SpendingChildPath,
  ): Result<CompactEcdsaSignature, Error> =
    Err(Error("AppBip322SighashSigner is not wired on iOS yet"))
}
