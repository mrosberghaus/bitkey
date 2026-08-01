package build.wallet.bitcoin.bip322

import build.wallet.bitcoin.verificationhash.SpendingChildPath
import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Result
import okio.ByteString

/** iOS placeholder until child-pubkey derivation is wired through the native FFI surface. */
@BitkeyInject(AppScope::class)
class SortedMultiScriptResolverUnsupported : SortedMultiScriptResolver {
  override suspend fun resolve(
    path: SpendingChildPath,
    expectedScriptPubKey: ByteString,
  ): Result<SortedMultiScript, Error> =
    Err(Error("SortedMultiScriptResolver is not wired on iOS yet"))
}
