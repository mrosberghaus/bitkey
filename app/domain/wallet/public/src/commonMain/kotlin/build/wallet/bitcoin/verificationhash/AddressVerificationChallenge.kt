package build.wallet.bitcoin.verificationhash

import build.wallet.bdk.bindings.BdkKeychainKind
import build.wallet.bitcoin.BitcoinNetworkType
import build.wallet.bitcoin.address.BitcoinAddress
import okio.Buffer
import okio.ByteString
import okio.ByteString.Companion.encodeUtf8

/**
 * Canonical tagged verification-hash payload and its SHA-256 digest.
 *
 * Digest is a single SHA-256 over [canonicalBytes] (not double-SHA256).
 * Signatures must ECDSA-sign this digest as the secp256k1 message (no extra hash).
 */
data class AddressVerificationChallenge(
  val version: UByte,
  val network: BitcoinNetworkType,
  val address: BitcoinAddress,
  val scriptPubKey: ByteString,
  val path: SpendingChildPath,
  val message: VerificationMessage,
  val canonicalBytes: ByteString,
  val digest: ByteString,
) {
  companion object {
    const val TAG: String = "BKAddressVerificationHash/v1"
    const val VERSION: UByte = 1u

    fun create(
      network: BitcoinNetworkType,
      address: BitcoinAddress,
      scriptPubKey: ByteString,
      path: SpendingChildPath,
      message: VerificationMessage,
      version: UByte = VERSION,
    ): AddressVerificationChallenge {
      val canonical = encodeCanonical(
        version = version,
        network = network,
        address = address,
        scriptPubKey = scriptPubKey,
        path = path,
        message = message
      )
      return AddressVerificationChallenge(
        version = version,
        network = network,
        address = address,
        scriptPubKey = scriptPubKey,
        path = path,
        message = message,
        canonicalBytes = canonical,
        digest = canonical.sha256()
      )
    }

    fun encodeCanonical(
      version: UByte,
      network: BitcoinNetworkType,
      address: BitcoinAddress,
      scriptPubKey: ByteString,
      path: SpendingChildPath,
      message: VerificationMessage,
    ): ByteString {
      val buffer = Buffer()
      val tag = TAG.encodeUtf8()
      buffer.writeInt(tag.size)
      buffer.write(tag)
      buffer.writeByte(version.toInt())
      buffer.writeByte(network.toWireByte().toInt())
      writeLengthPrefixedUtf8(buffer, address.address)
      writeLengthPrefixedBytes(buffer, scriptPubKey)
      buffer.writeByte(path.keychain.toWireByte().toInt())
      buffer.writeInt(path.index.toInt())
      writeLengthPrefixedUtf8(buffer, message.value)
      return buffer.readByteString()
    }
  }
}

internal fun BitcoinNetworkType.toWireByte(): UByte =
  when (this) {
    BitcoinNetworkType.BITCOIN -> 0u
    BitcoinNetworkType.TESTNET -> 1u
    BitcoinNetworkType.SIGNET -> 2u
    BitcoinNetworkType.REGTEST -> 3u
  }

internal fun bitcoinNetworkTypeFromWireByte(byte: UByte): BitcoinNetworkType? =
  when (byte) {
    0u.toUByte() -> BitcoinNetworkType.BITCOIN
    1u.toUByte() -> BitcoinNetworkType.TESTNET
    2u.toUByte() -> BitcoinNetworkType.SIGNET
    3u.toUByte() -> BitcoinNetworkType.REGTEST
    else -> null
  }

internal fun BdkKeychainKind.toWireByte(): UByte =
  when (this) {
    BdkKeychainKind.EXTERNAL -> 0u
    BdkKeychainKind.INTERNAL -> 1u
    else -> error("Unknown keychain kind: $this")
  }

internal fun keychainKindFromWireByte(byte: UByte): BdkKeychainKind? =
  when (byte) {
    0u.toUByte() -> BdkKeychainKind.EXTERNAL
    1u.toUByte() -> BdkKeychainKind.INTERNAL
    else -> null
  }

internal fun writeLengthPrefixedUtf8(
  buffer: Buffer,
  value: String,
) {
  val bytes = value.encodeUtf8()
  writeLengthPrefixedBytes(buffer, bytes)
}

internal fun writeLengthPrefixedBytes(
  buffer: Buffer,
  bytes: ByteString,
) {
  buffer.writeInt(bytes.size)
  buffer.write(bytes)
}

internal fun readLengthPrefixedBytes(buffer: Buffer): ByteString? {
  if (buffer.size < 4L) return null
  val length = buffer.readInt()
  if (length < 0 || buffer.size < length.toLong()) return null
  return buffer.readByteString(length.toLong())
}

internal fun readLengthPrefixedUtf8(buffer: Buffer): String? =
  readLengthPrefixedBytes(buffer)?.utf8()
