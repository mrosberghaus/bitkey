package build.wallet.bitcoin.attestation

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result

/**
 * User-facing attestation message. Non-blank UTF-8, max [MAX_LENGTH] code units.
 *
 * 280 matches a short social-style note without allowing large payloads into HW confirm UI.
 */
data class AttestationMessage private constructor(val value: String) {
  companion object {
    const val MAX_LENGTH: Int = 280

    fun create(value: String): Result<AttestationMessage, AttestationMessageError> {
      val trimmed = value.trim()
      if (trimmed.isEmpty()) {
        return Err(AttestationMessageError.Blank)
      }
      if (trimmed.length > MAX_LENGTH) {
        return Err(AttestationMessageError.TooLong(trimmed.length))
      }
      return Ok(AttestationMessage(trimmed))
    }
  }
}

sealed class AttestationMessageError : Error() {
  data object Blank : AttestationMessageError() {
    private fun readResolve(): Any = Blank
  }

  data class TooLong(val length: Int) : AttestationMessageError()
}
