package build.wallet.bitcoin.attestation

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.getOrThrow
import okio.ByteString

/**
 * 64-byte compact ECDSA signature: r (32) || s (32).
 */
data class CompactEcdsaSignature private constructor(val bytes: ByteString) {
  companion object {
    const val SIZE: Int = 64

    fun create(bytes: ByteString): Result<CompactEcdsaSignature, CompactEcdsaSignatureError> {
      if (bytes.size != SIZE) {
        return Err(CompactEcdsaSignatureError.InvalidLength(bytes.size))
      }
      return Ok(CompactEcdsaSignature(bytes))
    }

    fun createOrThrow(bytes: ByteString): CompactEcdsaSignature =
      create(bytes).getOrThrow()
  }
}

sealed class CompactEcdsaSignatureError : Error() {
  data class InvalidLength(val length: Int) : CompactEcdsaSignatureError()
}
