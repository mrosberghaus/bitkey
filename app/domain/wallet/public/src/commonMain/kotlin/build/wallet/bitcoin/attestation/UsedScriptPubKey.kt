package build.wallet.bitcoin.attestation

import build.wallet.bitcoin.BitcoinNetworkType
import build.wallet.bitcoin.address.BitcoinAddress
import okio.ByteString

/**
 * A scriptPubKey that has appeared in the wallet's transaction history (receive or change).
 */
data class UsedScriptPubKey(
  val network: BitcoinNetworkType,
  val address: BitcoinAddress,
  val scriptPubKey: ByteString,
  val path: SpendingChildPath,
)
