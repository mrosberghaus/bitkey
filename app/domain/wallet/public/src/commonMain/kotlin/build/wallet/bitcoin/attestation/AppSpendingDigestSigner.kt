package build.wallet.bitcoin.attestation

import com.github.michaelbull.result.Result
import okio.ByteString

/**
 * Signs a 32-byte attestation digest with the app spending child key at [path].
 *
 * Must ECDSA-sign the digest as the secp256k1 message. Must not SHA-256 the digest again
 * (do not pass the digest through [build.wallet.encrypt.MessageSigner]).
 */
fun interface AppSpendingDigestSigner {
  suspend fun signDigest(
    digest: ByteString,
    path: SpendingChildPath,
  ): Result<CompactEcdsaSignature, Error>
}
