package build.wallet.bitcoin.bip322

import build.wallet.account.AccountService
import build.wallet.account.getAccount
import build.wallet.bdk.bindings.BdkKeychainKind
import build.wallet.bitcoin.keys.DescriptorPublicKey
import build.wallet.bitkey.account.FullAccount
import build.wallet.catchingResult
import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import build.wallet.encrypt.Secp256k1PublicKey
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.coroutineBinding
import com.github.michaelbull.result.mapError
import okio.ByteString
import uniffi.bdk.DerivationPath
import uniffi.bdk.DescriptorPublicKey as BdkDescriptorPublicKey
import build.wallet.rust.core.extractPublicKey as coreExtractPublicKey

/**
 * Derives app/hw/server child pubkeys from the active spending keyset at [path],
 * BIP67-sorts them, and checks P2WSH(witnessScript) matches the used SPK.
 */
@BitkeyInject(AppScope::class)
class SortedMultiScriptResolverImpl(
  private val accountService: AccountService,
) : SortedMultiScriptResolver {
  override suspend fun resolve(
    path: SpendingChildPath,
    expectedScriptPubKey: ByteString,
  ): Result<SortedMultiScript, Error> =
    coroutineBinding {
      val account = accountService.getAccount<FullAccount>().bind()
      val keyset = account.keybox.activeSpendingKeyset

      val app = deriveChildPubkey(keyset.appKey.key, path).bind()
      val hw = deriveChildPubkey(keyset.hardwareKey.key, path).bind()
      val server = deriveChildPubkey(keyset.f8eSpendingKeyset.spendingPublicKey.key, path).bind()

      val script = SortedMultiScript.fromChildPubkeys(app = app, hw = hw, server = server).bind()
      val actualSpk = SortedMultiScript.p2wshScriptPubKey(script.witnessScript)
      if (actualSpk != expectedScriptPubKey) {
        Err(
          Error(
            "Resolved sortedmulti scriptPubKey mismatch at ${path.keychain}/${path.index}: " +
              "expected ${expectedScriptPubKey.hex()}, got ${actualSpk.hex()}"
          )
        ).bind()
      }

      script
    }
}

private fun deriveChildPubkey(
  accountDpub: DescriptorPublicKey,
  path: SpendingChildPath,
): Result<Secp256k1PublicKey, Error> =
  catchingResult {
    val accountKey = BdkDescriptorPublicKey.fromString(accountDpub.dpub)
    val childPath = DerivationPath("m/${path.keychain.toChildNumber()}/${path.index}")
    val derived = accountKey.derive(childPath)
    val hex = coreExtractPublicKey(derived.toString())
    Secp256k1PublicKey(hex)
  }.mapError {
    Error(
      "Failed to derive spending child pubkey at ${path.keychain}/${path.index}: ${it.message}",
      it
    )
  }

private fun BdkKeychainKind.toChildNumber(): UInt =
  when (this) {
    BdkKeychainKind.EXTERNAL -> 0u
    BdkKeychainKind.INTERNAL -> 1u
  }
