package build.wallet.bitcoin.bip322

import com.github.michaelbull.result.Result
import okio.ByteString

/**
 * Resolve BIP67-ordered script material for the active keyset at [path].
 *
 * Implementations must produce a [SortedMultiScript] whose P2WSH program matches
 * [expectedScriptPubKey].
 */
fun interface SortedMultiScriptResolver {
  suspend fun resolve(
    path: SpendingChildPath,
    expectedScriptPubKey: ByteString,
  ): Result<SortedMultiScript, Error>
}
