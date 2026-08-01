package build.wallet.bitcoin.verificationhash

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
 * Versioned Bitkey-internal verification hash (app + HW spending-key signatures).
 *
 * Wire format (length-prefixed, big-endian lengths):
 * version(u8) | network(u8) | address | scriptPubKey | keychain(u8) | index(u32) |
 * message | digest(32) | appSignature(64) | hwSignature(64)
 */
data class AddressVerificationHash(
  val version: UByte,
  val network: BitcoinNetworkType,
  val address: BitcoinAddress,
  val scriptPubKey: ByteString,
  val path: SpendingChildPath,
  val message: VerificationMessage,
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
    fun decode(bytes: ByteString): Result<AddressVerificationHash, AddressVerificationHashDecodeError> {
      val buffer = Buffer().write(bytes)
      if (buffer.size < 1L) return Err(AddressVerificationHashDecodeError.Truncated)
      val version = buffer.readByte().toUByte()
      if (buffer.size < 1L) return Err(AddressVerificationHashDecodeError.Truncated)
      val networkByte = buffer.readByte().toUByte()
      val network = bitcoinNetworkTypeFromWireByte(networkByte)
        ?: return Err(AddressVerificationHashDecodeError.InvalidNetwork(networkByte))

      val addressStr = readLengthPrefixedUtf8(buffer)
        ?: return Err(AddressVerificationHashDecodeError.Truncated)
      val scriptPubKey = readLengthPrefixedBytes(buffer)
        ?: return Err(AddressVerificationHashDecodeError.Truncated)
      if (buffer.size < 1L) return Err(AddressVerificationHashDecodeError.Truncated)
      val keychainByte = buffer.readByte().toUByte()
      val keychain = keychainKindFromWireByte(keychainByte)
        ?: return Err(AddressVerificationHashDecodeError.InvalidKeychain(keychainByte))
      if (buffer.size < 4L) return Err(AddressVerificationHashDecodeError.Truncated)
      val index = buffer.readInt().toUInt()
      val messageStr = readLengthPrefixedUtf8(buffer)
        ?: return Err(AddressVerificationHashDecodeError.Truncated)
      val messageResult = VerificationMessage.create(messageStr)
      val message = messageResult.get()
        ?: return Err(
          AddressVerificationHashDecodeError.InvalidMessage(
            messageResult.getError() ?: VerificationMessageError.Blank
          )
        )
      if (buffer.size < 32L) return Err(AddressVerificationHashDecodeError.Truncated)
      val digest = buffer.readByteString(32)
      if (buffer.size < CompactEcdsaSignature.SIZE.toLong()) {
        return Err(AddressVerificationHashDecodeError.Truncated)
      }
      val appSigBytes = buffer.readByteString(CompactEcdsaSignature.SIZE.toLong())
      if (buffer.size < CompactEcdsaSignature.SIZE.toLong()) {
        return Err(AddressVerificationHashDecodeError.Truncated)
      }
      val hwSigBytes = buffer.readByteString(CompactEcdsaSignature.SIZE.toLong())
      if (buffer.size != 0L) return Err(AddressVerificationHashDecodeError.TrailingBytes)

      val appSignatureResult = CompactEcdsaSignature.create(appSigBytes)
      val appSignature = appSignatureResult.get()
        ?: return Err(
          AddressVerificationHashDecodeError.InvalidSignature(
            appSignatureResult.getError()
              ?: CompactEcdsaSignatureError.InvalidLength(appSigBytes.size)
          )
        )
      val hwSignatureResult = CompactEcdsaSignature.create(hwSigBytes)
      val hwSignature = hwSignatureResult.get()
        ?: return Err(
          AddressVerificationHashDecodeError.InvalidSignature(
            hwSignatureResult.getError()
              ?: CompactEcdsaSignatureError.InvalidLength(hwSigBytes.size)
          )
        )

      return Ok(
        AddressVerificationHash(
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
      verificationHash: AddressVerificationHash,
      watchingExternal: WatchingVerificationKeychain,
      watchingInternal: WatchingVerificationKeychain,
      ecdsa: VerificationHashEcdsaCrypto,
    ): AddressVerificationHashResult {
      val reasons = mutableListOf<AddressVerificationHashInvalidReason>()

      val challenge = AddressVerificationChallenge.create(
        network = verificationHash.network,
        address = verificationHash.address,
        scriptPubKey = verificationHash.scriptPubKey,
        path = verificationHash.path,
        message = verificationHash.message,
        version = verificationHash.version
      )
      if (challenge.digest != verificationHash.digest) {
        reasons += AddressVerificationHashInvalidReason.DigestMismatch
      }

      val watching = when (verificationHash.path.keychain) {
        BdkKeychainKind.EXTERNAL -> watchingExternal
        BdkKeychainKind.INTERNAL -> watchingInternal
        else -> {
          reasons += AddressVerificationHashInvalidReason.AddressMismatch
          watchingExternal
        }
      }

      val expectedAddress = watching.addressAt(verificationHash.path.index)
      if (expectedAddress == null || expectedAddress != verificationHash.address) {
        reasons += AddressVerificationHashInvalidReason.AddressMismatch
      }

      val expectedSpk = watching.scriptPubKeyAt(verificationHash.path.index)
      if (expectedSpk == null || expectedSpk != verificationHash.scriptPubKey) {
        reasons += AddressVerificationHashInvalidReason.ScriptPubKeyMismatch
      }

      val appPublicKey = watching.appPublicKeyAt(verificationHash.path.index)
      if (appPublicKey == null) {
        reasons += AddressVerificationHashInvalidReason.MissingAppPublicKey
      } else if (
        !ecdsa.verifyDigest(
          digest = verificationHash.digest,
          signature = verificationHash.appSignature,
          publicKey = appPublicKey
        )
      ) {
        reasons += AddressVerificationHashInvalidReason.InvalidAppSignature
      }

      val hwPublicKey = watching.hwPublicKeyAt(verificationHash.path.index)
      if (hwPublicKey == null) {
        reasons += AddressVerificationHashInvalidReason.MissingHwPublicKey
      } else if (
        !ecdsa.verifyDigest(
          digest = verificationHash.digest,
          signature = verificationHash.hwSignature,
          publicKey = hwPublicKey
        )
      ) {
        reasons += AddressVerificationHashInvalidReason.InvalidHwSignature
      }

      return if (reasons.isEmpty()) {
        AddressVerificationHashResult.Valid
      } else {
        AddressVerificationHashResult.Invalid(reasons)
      }
    }
  }
}

sealed class AddressVerificationHashDecodeError : Error() {
  data object Truncated : AddressVerificationHashDecodeError() {
    private fun readResolve(): Any = Truncated
  }

  data class InvalidNetwork(val byte: UByte) : AddressVerificationHashDecodeError()

  data class InvalidKeychain(val byte: UByte) : AddressVerificationHashDecodeError()

  data class InvalidMessage(
    override val cause: VerificationMessageError,
  ) : AddressVerificationHashDecodeError()

  data class InvalidSignature(
    override val cause: CompactEcdsaSignatureError,
  ) : AddressVerificationHashDecodeError()

  data object TrailingBytes : AddressVerificationHashDecodeError() {
    private fun readResolve(): Any = TrailingBytes
  }
}
