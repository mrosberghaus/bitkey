package build.wallet.bitcoin.verificationhash

import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Result
import okio.ByteString

/** iOS placeholder until core digest signing is wired through the native FFI surface. */
@BitkeyInject(AppScope::class)
class AppSpendingDigestSignerUnsupported : AppSpendingDigestSigner {
  override suspend fun signDigest(
    digest: ByteString,
    path: SpendingChildPath,
  ): Result<CompactEcdsaSignature, Error> =
    Err(Error("AppSpendingDigestSigner is not wired on iOS yet"))
}
