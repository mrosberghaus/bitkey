package build.wallet.bitcoin.verificationhash

import build.wallet.account.AccountService
import build.wallet.account.getAccount
import build.wallet.bdk.bindings.BdkKeychainKind
import build.wallet.bitcoin.AppPrivateKeyDao
import build.wallet.bitkey.account.FullAccount
import build.wallet.catchingResult
import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import build.wallet.toByteString
import build.wallet.toUByteList
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.coroutineBinding
import com.github.michaelbull.result.mapError
import com.github.michaelbull.result.toErrorIfNull
import okio.ByteString
import uniffi.bdk.DerivationPath
import uniffi.bdk.DescriptorSecretKey
import build.wallet.rust.core.SecretKey as CoreSecretKey

@BitkeyInject(AppScope::class)
class AppSpendingDigestSignerImpl(
  private val accountService: AccountService,
  private val appPrivateKeyDao: AppPrivateKeyDao,
) : AppSpendingDigestSigner {
  override suspend fun signDigest(
    digest: ByteString,
    path: SpendingChildPath,
  ): Result<CompactEcdsaSignature, Error> {
    if (digest.size != 32) {
      return Err(Error("Verification-hash digest must be 32 bytes, got ${digest.size}"))
    }

    return coroutineBinding {
      val account = accountService.getAccount<FullAccount>().bind()
      val appPublicKey = account.keybox.activeSpendingKeyset.appKey
      val appPrivateKey =
        appPrivateKeyDao
          .getAppSpendingPrivateKey(appPublicKey)
          .mapError { Error(it.message, it) }
          .toErrorIfNull { Error("App spending private key not found for active keyset") }
          .bind()

      val childSecretBytes =
        catchingResult {
          val accountXprv = DescriptorSecretKey.fromString(appPrivateKey.key.xprv)
          val childPath = DerivationPath("m/${path.keychain.toChildNumber()}/${path.index}")
          accountXprv.derive(childPath).secretBytes()
        }
          .mapError {
            Error(
              "Failed to derive spending child at ${path.keychain}/${path.index}: ${it.message}",
              it
            )
          }
          .bind()

      val compact =
        catchingResult {
          CoreSecretKey(childSecretBytes.toUByteList())
            .signDigest(digest.toUByteList())
            .toByteString()
        }
          .mapError { Error("Failed to sign verification-hash digest: ${it.message}", it) }
          .bind()

      CompactEcdsaSignature.create(compact)
        .mapError { Error("Invalid compact signature from digest signer: $it") }
        .bind()
    }
  }
}

private fun BdkKeychainKind.toChildNumber(): UInt =
  when (this) {
    BdkKeychainKind.EXTERNAL -> 0u
    BdkKeychainKind.INTERNAL -> 1u
  }
