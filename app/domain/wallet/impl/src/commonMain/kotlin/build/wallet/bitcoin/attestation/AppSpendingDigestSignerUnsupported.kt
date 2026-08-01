package build.wallet.bitcoin.attestation

import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Result
import okio.ByteString

/** DI placeholder until BIP32 child digest signing is wired with the UI/NFC slice. */
@BitkeyInject(AppScope::class)
class AppSpendingDigestSignerUnsupported : AppSpendingDigestSigner {
  override suspend fun signDigest(
    digest: ByteString,
    path: SpendingChildPath,
  ): Result<CompactEcdsaSignature, Error> =
    Err(Error("AppSpendingDigestSigner is not wired; inject a raw digest ECDSA signer"))
}
