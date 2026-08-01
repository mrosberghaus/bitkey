package build.wallet.bitcoin.verificationhash

import build.wallet.bitcoin.address.BitcoinAddress
import build.wallet.encrypt.Secp256k1PublicKey
import okio.ByteString

/**
 * Watching material for one keychain (external or internal), keyed by address index.
 * Callers supply already-derived child keys and expected script/address for pure verify.
 */
data class WatchingVerificationKeychain(
  val addressAt: (index: UInt) -> BitcoinAddress?,
  val scriptPubKeyAt: (index: UInt) -> ByteString?,
  val appPublicKeyAt: (index: UInt) -> Secp256k1PublicKey?,
  val hwPublicKeyAt: (index: UInt) -> Secp256k1PublicKey?,
) {
  companion object {
    fun of(
      addresses: Map<UInt, BitcoinAddress> = emptyMap(),
      scriptPubKeys: Map<UInt, ByteString> = emptyMap(),
      appPublicKeys: Map<UInt, Secp256k1PublicKey> = emptyMap(),
      hwPublicKeys: Map<UInt, Secp256k1PublicKey> = emptyMap(),
    ): WatchingVerificationKeychain =
      WatchingVerificationKeychain(
        addressAt = addresses::get,
        scriptPubKeyAt = scriptPubKeys::get,
        appPublicKeyAt = appPublicKeys::get,
        hwPublicKeyAt = hwPublicKeys::get
      )
  }
}
