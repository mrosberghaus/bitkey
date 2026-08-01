package build.wallet.bitcoin.bip322

import build.wallet.bitcoin.verificationhash.CompactEcdsaSignature
import build.wallet.bitcoin.verificationhash.SpendingChildPath
import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Result

/** iOS placeholder until digest signing is wired through the native FFI surface. */
@BitkeyInject(AppScope::class)
class AppBip322SighashSignerUnsupported : AppBip322SighashSigner {
  override suspend fun sign(
    sighash: Bip322Sighash,
    path: SpendingChildPath,
  ): Result<CompactEcdsaSignature, Error> =
    Err(Error("AppBip322SighashSigner is not wired on iOS yet"))
}
