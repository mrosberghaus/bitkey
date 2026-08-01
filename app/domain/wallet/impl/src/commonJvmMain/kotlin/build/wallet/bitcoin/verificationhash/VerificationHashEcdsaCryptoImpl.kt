package build.wallet.bitcoin.verificationhash

import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import build.wallet.encrypt.Secp256k1PublicKey
import build.wallet.rust.core.SignatureVerifierException
import build.wallet.rust.core.verifyEcdsaDigest
import build.wallet.toUByteList
import okio.ByteString
import okio.ByteString.Companion.decodeHex

@BitkeyInject(AppScope::class)
class VerificationHashEcdsaCryptoImpl : VerificationHashEcdsaCrypto {
  override fun verifyDigest(
    digest: ByteString,
    signature: CompactEcdsaSignature,
    publicKey: Secp256k1PublicKey,
  ): Boolean {
    if (digest.size != 32) return false
    return try {
      verifyEcdsaDigest(
        digest.toByteArray(),
        signature.bytes.toUByteList(),
        publicKey.value.decodeHex().toByteArray()
      )
      true
    } catch (_: SignatureVerifierException) {
      false
    } catch (_: IllegalArgumentException) {
      false
    }
  }
}
