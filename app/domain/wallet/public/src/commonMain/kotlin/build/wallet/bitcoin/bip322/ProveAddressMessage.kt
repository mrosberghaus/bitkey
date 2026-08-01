package build.wallet.bitcoin.bip322

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result

/**
 * User message for BIP-322 prove-address. Non-blank trimmed UTF-8, max [MAX_LENGTH] code units.
 *
 * 280 matches HW display bounds (same as verification-hash [build.wallet.bitcoin.verificationhash.VerificationMessage]).
 */
data class ProveAddressMessage private constructor(val value: String) {
  companion object {
    const val MAX_LENGTH: Int = 280

    fun create(value: String): Result<ProveAddressMessage, ProveAddressMessageError> {
      val trimmed = value.trim()
      if (trimmed.isEmpty()) {
        return Err(ProveAddressMessageError.Blank)
      }
      if (trimmed.length > MAX_LENGTH) {
        return Err(ProveAddressMessageError.TooLong(trimmed.length))
      }
      return Ok(ProveAddressMessage(trimmed))
    }
  }
}

sealed class ProveAddressMessageError : Error() {
  data object Blank : ProveAddressMessageError() {
    private fun readResolve(): Any = Blank
  }

  data class TooLong(val length: Int) : ProveAddressMessageError()
}
