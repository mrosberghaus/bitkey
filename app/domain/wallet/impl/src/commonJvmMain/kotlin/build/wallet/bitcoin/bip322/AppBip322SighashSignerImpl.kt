package build.wallet.bitcoin.bip322

import build.wallet.bitcoin.verificationhash.AppSpendingDigestSigner
import build.wallet.bitcoin.verificationhash.CompactEcdsaSignature
import build.wallet.bitcoin.verificationhash.SpendingChildPath
import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import com.github.michaelbull.result.Result

/**
 * Adapts [AppSpendingDigestSigner]: same ECDSA-over-32-bytes, no rehash.
 */
@BitkeyInject(AppScope::class)
class AppBip322SighashSignerImpl(
  private val digestSigner: AppSpendingDigestSigner,
) : AppBip322SighashSigner {
  override suspend fun sign(
    sighash: Bip322Sighash,
    path: SpendingChildPath,
  ): Result<CompactEcdsaSignature, Error> =
    digestSigner.signDigest(digest = sighash.bytes, path = path)
}
