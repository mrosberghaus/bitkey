package build.wallet.bitcoin.attestation

import build.wallet.bdk.bindings.BdkKeychainKind
import build.wallet.bitcoin.BitcoinNetworkType
import build.wallet.bitcoin.address.BitcoinAddress
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.get
import com.github.michaelbull.result.getError
import okio.Buffer
import okio.ByteString

/**
 * Versioned Bitkey-internal address attestation (app + HW spending-key signatures).
 *
 * Wire format (length-prefixed, big-endian lengths):
 * version(u8) | network(u8) | address | scriptPubKey | keychain(u8) | index(u32) |
 * message | digest(32) | appSignature(64) | hwSignature(64)
 */
data class AddressAttestation(
  val version: UByte,
  val network: BitcoinNetworkType,
  val address: BitcoinAddress,
  val scriptPubKey: ByteString,
  val path: SpendingChildPath,
  val message: AttestationMessage,
  val digest: ByteString,
  val appSignature: CompactEcdsaSignature,
  val hwSignature: CompactEcdsaSignature,
) {
  fun encode(): ByteString {
    val buffer = Buffer()
    buffer.writeByte(version.toInt())
    buffer.writeByte(network.toWireByte().toInt())
    writeLengthPrefixedUtf8(buffer, address.address)
    writeLengthPrefixedBytes(buffer, scriptPubKey)
    buffer.writeByte(path.keychain.toWireByte().toInt())
    buffer.writeInt(path.index.toInt())
    writeLengthPrefixedUtf8(buffer, message.value)
    require(digest.size == 32) { "digest must be 32 bytes" }
    buffer.write(digest)
    buffer.write(appSignature.bytes)
    buffer.write(hwSignature.bytes)
    return buffer.readByteString()
  }

  companion object {
    fun decode(bytes: ByteString): Result<AddressAttestation, AddressAttestationDecodeError> {
      val buffer = Buffer().write(bytes)
      if (buffer.size < 1L) return Err(AddressAttestationDecodeError.Truncated)
      val version = buffer.readByte().toUByte()
      if (buffer.size < 1L) return Err(AddressAttestationDecodeError.Truncated)
      val networkByte = buffer.readByte().toUByte()
      val network = bitcoinNetworkTypeFromWireByte(networkByte)
        ?: return Err(AddressAttestationDecodeError.InvalidNetwork(networkByte))

      val addressStr = readLengthPrefixedUtf8(buffer)
        ?: return Err(AddressAttestationDecodeError.Truncated)
      val scriptPubKey = readLengthPrefixedBytes(buffer)
        ?: return Err(AddressAttestationDecodeError.Truncated)
      if (buffer.size < 1L) return Err(AddressAttestationDecodeError.Truncated)
      val keychainByte = buffer.readByte().toUByte()
      val keychain = keychainKindFromWireByte(keychainByte)
        ?: return Err(AddressAttestationDecodeError.InvalidKeychain(keychainByte))
      if (buffer.size < 4L) return Err(AddressAttestationDecodeError.Truncated)
      val index = buffer.readInt().toUInt()
      val messageStr = readLengthPrefixedUtf8(buffer)
        ?: return Err(AddressAttestationDecodeError.Truncated)
      val messageResult = AttestationMessage.create(messageStr)
      val message = messageResult.get()
        ?: return Err(
          AddressAttestationDecodeError.InvalidMessage(
            messageResult.getError() ?: AttestationMessageError.Blank
          )
        )
      if (buffer.size < 32L) return Err(AddressAttestationDecodeError.Truncated)
      val digest = buffer.readByteString(32)
      if (buffer.size < CompactEcdsaSignature.SIZE.toLong()) {
        return Err(AddressAttestationDecodeError.Truncated)
      }
      val appSigBytes = buffer.readByteString(CompactEcdsaSignature.SIZE.toLong())
      if (buffer.size < CompactEcdsaSignature.SIZE.toLong()) {
        return Err(AddressAttestationDecodeError.Truncated)
      }
      val hwSigBytes = buffer.readByteString(CompactEcdsaSignature.SIZE.toLong())
      if (buffer.size != 0L) return Err(AddressAttestationDecodeError.TrailingBytes)

      val appSignatureResult = CompactEcdsaSignature.create(appSigBytes)
      val appSignature = appSignatureResult.get()
        ?: return Err(
          AddressAttestationDecodeError.InvalidSignature(
            appSignatureResult.getError()
              ?: CompactEcdsaSignatureError.InvalidLength(appSigBytes.size)
          )
        )
      val hwSignatureResult = CompactEcdsaSignature.create(hwSigBytes)
      val hwSignature = hwSignatureResult.get()
        ?: return Err(
          AddressAttestationDecodeError.InvalidSignature(
            hwSignatureResult.getError()
              ?: CompactEcdsaSignatureError.InvalidLength(hwSigBytes.size)
          )
        )

      return Ok(
        AddressAttestation(
          version = version,
          network = network,
          address = BitcoinAddress(addressStr),
          scriptPubKey = scriptPubKey,
          path = SpendingChildPath(keychain = keychain, index = index),
          message = message,
          digest = digest,
          appSignature = appSignature,
          hwSignature = hwSignature
        )
      )
    }

    /**
     * Verify against watching external/internal key material.
     * [ecdsa] must verify compact ECDSA over the 32-byte digest with no extra hash.
     */
    fun verify(
      attestation: AddressAttestation,
      watchingExternal: WatchingAttestationKeychain,
      watchingInternal: WatchingAttestationKeychain,
      ecdsa: AttestationEcdsaCrypto,
    ): AddressAttestationVerification {
      val reasons = mutableListOf<AddressAttestationInvalidReason>()

      val challenge = AddressAttestationChallenge.create(
        network = attestation.network,
        address = attestation.address,
        scriptPubKey = attestation.scriptPubKey,
        path = attestation.path,
        message = attestation.message,
        version = attestation.version
      )
      if (challenge.digest != attestation.digest) {
        reasons += AddressAttestationInvalidReason.DigestMismatch
      }

      val watching = when (attestation.path.keychain) {
        BdkKeychainKind.EXTERNAL -> watchingExternal
        BdkKeychainKind.INTERNAL -> watchingInternal
        else -> {
          reasons += AddressAttestationInvalidReason.AddressMismatch
          watchingExternal
        }
      }

      val expectedAddress = watching.addressAt(attestation.path.index)
      if (expectedAddress == null || expectedAddress != attestation.address) {
        reasons += AddressAttestationInvalidReason.AddressMismatch
      }

      val expectedSpk = watching.scriptPubKeyAt(attestation.path.index)
      if (expectedSpk == null || expectedSpk != attestation.scriptPubKey) {
        reasons += AddressAttestationInvalidReason.ScriptPubKeyMismatch
      }

      val appPublicKey = watching.appPublicKeyAt(attestation.path.index)
      if (appPublicKey == null) {
        reasons += AddressAttestationInvalidReason.MissingAppPublicKey
      } else if (
        !ecdsa.verifyDigest(
          digest = attestation.digest,
          signature = attestation.appSignature,
          publicKey = appPublicKey
        )
      ) {
        reasons += AddressAttestationInvalidReason.InvalidAppSignature
      }

      val hwPublicKey = watching.hwPublicKeyAt(attestation.path.index)
      if (hwPublicKey == null) {
        reasons += AddressAttestationInvalidReason.MissingHwPublicKey
      } else if (
        !ecdsa.verifyDigest(
          digest = attestation.digest,
          signature = attestation.hwSignature,
          publicKey = hwPublicKey
        )
      ) {
        reasons += AddressAttestationInvalidReason.InvalidHwSignature
      }

      return if (reasons.isEmpty()) {
        AddressAttestationVerification.Valid
      } else {
        AddressAttestationVerification.Invalid(reasons)
      }
    }
  }
}

sealed class AddressAttestationDecodeError : Error() {
  data object Truncated : AddressAttestationDecodeError() {
    private fun readResolve(): Any = Truncated
  }

  data class InvalidNetwork(val byte: UByte) : AddressAttestationDecodeError()

  data class InvalidKeychain(val byte: UByte) : AddressAttestationDecodeError()

  data class InvalidMessage(
    override val cause: AttestationMessageError,
  ) : AddressAttestationDecodeError()

  data class InvalidSignature(
    override val cause: CompactEcdsaSignatureError,
  ) : AddressAttestationDecodeError()

  data object TrailingBytes : AddressAttestationDecodeError() {
    private fun readResolve(): Any = TrailingBytes
  }
}
