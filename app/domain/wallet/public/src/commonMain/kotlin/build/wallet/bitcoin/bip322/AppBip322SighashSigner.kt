package build.wallet.bitcoin.bip322

import com.github.michaelbull.result.Result

/**
 * App spending-key signer for a BIP-322 sighash.
 *
 * Must ECDSA-sign the 32 bytes as the secp256k1 message (no extra SHA-256).
 * Must not use auth MessageSigner / signChallenge.
 */
fun interface AppBip322SighashSigner {
  suspend fun sign(
    sighash: Bip322Sighash,
    path: SpendingChildPath,
  ): Result<CompactEcdsaSignature, Error>
}
