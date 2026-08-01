package build.wallet.bitcoin.verificationhash

import build.wallet.encrypt.Secp256k1PublicKey
import okio.ByteString

/**
 * Compact ECDSA over a pre-hashed 32-byte digest (secp256k1 message = digest, no extra hash).
 *
 * Do not implement with [build.wallet.encrypt.MessageSigner] / [build.wallet.encrypt.SignatureVerifier]
 * by passing the digest as a "message" — those APIs SHA-256 again.
 */
fun interface VerificationHashEcdsaCrypto {
  fun verifyDigest(
    digest: ByteString,
    signature: CompactEcdsaSignature,
    publicKey: Secp256k1PublicKey,
  ): Boolean
}
