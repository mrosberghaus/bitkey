package build.wallet.bitcoin.bip322

import build.wallet.bdk.bindings.BdkKeychainKind

/**
 * BIP84-style child path under the account descriptor: keychain (receive/change) + address index.
 */
data class SpendingChildPath(
  val keychain: BdkKeychainKind,
  val index: UInt,
)
