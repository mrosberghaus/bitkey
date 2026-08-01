package build.wallet.bitcoin.attestation

import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import build.wallet.encrypt.Secp256k1PublicKey
import okio.ByteString

/** iOS placeholder until compact digest verify is wired through the native FFI surface. */
@BitkeyInject(AppScope::class)
class AttestationEcdsaCryptoUnsupported : AttestationEcdsaCrypto {
  override fun verifyDigest(
    digest: ByteString,
    signature: CompactEcdsaSignature,
    publicKey: Secp256k1PublicKey,
  ): Boolean = false
}
