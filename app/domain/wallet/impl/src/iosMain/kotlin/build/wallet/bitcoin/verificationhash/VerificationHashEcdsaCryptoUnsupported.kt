package build.wallet.bitcoin.verificationhash

import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import build.wallet.encrypt.Secp256k1PublicKey
import okio.ByteString

/** iOS placeholder until compact digest verify is wired through the native FFI surface. */
@BitkeyInject(AppScope::class)
class VerificationHashEcdsaCryptoUnsupported : VerificationHashEcdsaCrypto {
  override fun verifyDigest(
    digest: ByteString,
    signature: CompactEcdsaSignature,
    publicKey: Secp256k1PublicKey,
  ): Boolean = false
}
