package build.wallet.bitcoin.verificationhash

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result

/**
 * User-facing verification message. Non-blank UTF-8, max [MAX_LENGTH] code units.
 *
 * 280 matches a short social-style note without allowing large payloads into HW confirm UI.
 */
data class VerificationMessage private constructor(val value: String) {
  companion object {
    const val MAX_LENGTH: Int = 280

    fun create(value: String): Result<VerificationMessage, VerificationMessageError> {
      val trimmed = value.trim()
      if (trimmed.isEmpty()) {
        return Err(VerificationMessageError.Blank)
      }
      if (trimmed.length > MAX_LENGTH) {
        return Err(VerificationMessageError.TooLong(trimmed.length))
      }
      return Ok(VerificationMessage(trimmed))
    }
  }
}

sealed class VerificationMessageError : Error() {
  data object Blank : VerificationMessageError() {
    private fun readResolve(): Any = Blank
  }

  data class TooLong(val length: Int) : VerificationMessageError()
}
