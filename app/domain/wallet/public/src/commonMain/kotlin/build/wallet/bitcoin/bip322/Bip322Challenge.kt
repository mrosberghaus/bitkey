package build.wallet.bitcoin.bip322

import build.wallet.bitcoin.BitcoinNetworkType
import build.wallet.bitcoin.address.BitcoinAddress
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import okio.ByteString
import okio.ByteString.Companion.encodeUtf8

/**
 * Pure BIP-322 challenge for one used SPK + message + sortedmulti script material.
 *
 * Owns virtual txs and the segwit v0 sighash (scriptCode = witnessScript for P2WSH).
 */
data class Bip322Challenge(
  val network: BitcoinNetworkType,
  val address: BitcoinAddress,
  val scriptPubKey: ByteString,
  val path: SpendingChildPath,
  val message: ProveAddressMessage,
  val toSpend: ByteString,
  val toSign: ByteString,
  val sighash: Bip322Sighash,
  val script: SortedMultiScript,
) {
  companion object {
    fun create(
      usedSpk: UsedScriptPubKey,
      message: ProveAddressMessage,
      script: SortedMultiScript,
    ): Result<Bip322Challenge, Error> {
      val expectedSpk = SortedMultiScript.p2wshScriptPubKey(script.witnessScript)
      if (expectedSpk != usedSpk.scriptPubKey) {
        return Err(
          Error(
            "witnessScript does not hash to used scriptPubKey " +
              "(expected ${expectedSpk.hex()}, got ${usedSpk.scriptPubKey.hex()})"
          )
        )
      }

      val virtual = Bip322VirtualTransactions.create(
        message = message.value.encodeUtf8(),
        scriptPubKey = usedSpk.scriptPubKey
      )
      val sighash = Bip322SegwitV0Sighash.compute(
        virtual = virtual,
        scriptCode = Bip322SegwitV0Sighash.p2wshScriptCode(script.witnessScript)
      )

      return Ok(
        Bip322Challenge(
          network = usedSpk.network,
          address = usedSpk.address,
          scriptPubKey = usedSpk.scriptPubKey,
          path = usedSpk.path,
          message = message,
          toSpend = virtual.toSpend,
          toSign = virtual.toSign,
          sighash = sighash,
          script = script
        )
      )
    }
  }
}
