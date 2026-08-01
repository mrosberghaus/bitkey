package build.wallet.bitcoin.bip322

import okio.Buffer
import okio.ByteString
import okio.ByteString.Companion.encodeUtf8
import okio.ByteString.Companion.toByteString

/**
 * BIP-322 virtual `to_spend` / `to_sign` pair for one scriptPubKey + message.
 *
 * Pure construction: no signing, no network, no PSBT. Txids are Bitcoin display-order
 * (byte-reversed double-SHA256 of the legacy serialization), matching BIP test vectors.
 */
data class Bip322VirtualTransactions(
  val messageHash: ByteString,
  val toSpend: ByteString,
  val toSpendTxid: ByteString,
  val toSign: ByteString,
  val toSignTxid: ByteString,
) {
  init {
    require(messageHash.size == 32) { "message_hash must be 32 bytes" }
    require(toSpendTxid.size == 32) { "to_spend txid must be 32 bytes" }
    require(toSignTxid.size == 32) { "to_sign txid must be 32 bytes" }
  }

  companion object {
    const val MESSAGE_TAG: String = "BIP0322-signed-message"

    /**
     * Build virtual txs per BIP-322.
     *
     * [message] is UTF-8 bytes as-is (no length prefix). Empty message is allowed.
     * [scriptPubKey] is the address challenge script (message_challenge).
     */
    fun create(
      message: ByteString,
      scriptPubKey: ByteString,
    ): Bip322VirtualTransactions {
      val messageHash = bip340TaggedHash(MESSAGE_TAG.encodeUtf8(), message)
      val toSpend = encodeToSpend(messageHash, scriptPubKey)
      val toSpendTxidInternal = hash256(toSpend)
      val toSign = encodeToSign(toSpendTxidInternal)
      val toSignTxidInternal = hash256(toSign)
      return Bip322VirtualTransactions(
        messageHash = messageHash,
        toSpend = toSpend,
        toSpendTxid = toSpendTxidInternal.reversedBytes(),
        toSign = toSign,
        toSignTxid = toSignTxidInternal.reversedBytes()
      )
    }
  }
}

/**
 * BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg).
 */
fun bip340TaggedHash(
  tag: ByteString,
  message: ByteString,
): ByteString {
  val tagHash = tag.sha256()
  return Buffer()
    .write(tagHash)
    .write(tagHash)
    .write(message)
    .readByteString()
    .sha256()
}

internal fun hash256(bytes: ByteString): ByteString = bytes.sha256().sha256()

internal fun ByteString.reversedBytes(): ByteString =
  toByteArray().reversedArray().toByteString()

/**
 * to_spend: nVersion=0, coinbase-like vin committing to message_hash, vout[0]=spk value 0.
 */
internal fun encodeToSpend(
  messageHash: ByteString,
  scriptPubKey: ByteString,
): ByteString {
  require(messageHash.size == 32)
  val scriptSig = Buffer()
    .writeByte(0x00) // OP_0
    .writeByte(0x20) // PUSH32
    .write(messageHash)
    .readByteString()

  return Buffer().apply {
    writeIntLe(0) // nVersion
    writeCompactSize(1) // vin count
    write(ByteArray(32).toByteString()) // null prevout hash
    writeIntLe(0xFFFFFFFF.toInt()) // null prevout index
    writeCompactSize(scriptSig.size)
    write(scriptSig)
    writeIntLe(0) // nSequence
    writeCompactSize(1) // vout count
    writeLongLe(0) // value
    writeCompactSize(scriptPubKey.size)
    write(scriptPubKey)
    writeIntLe(0) // nLockTime
  }.readByteString()
}

/**
 * to_sign (unsigned): vin prevout=to_spend:0, empty scriptSig, vout OP_RETURN.
 * [toSpendTxidInternal] is the internal (little-endian) txid bytes.
 */
internal fun encodeToSign(toSpendTxidInternal: ByteString): ByteString {
  require(toSpendTxidInternal.size == 32)
  val opReturn = byteArrayOf(0x6a).toByteString()
  return Buffer().apply {
    writeIntLe(0) // nVersion
    writeCompactSize(1)
    write(toSpendTxidInternal)
    writeIntLe(0) // vout
    writeCompactSize(0) // empty scriptSig
    writeIntLe(0) // nSequence
    writeCompactSize(1)
    writeLongLe(0)
    writeCompactSize(opReturn.size)
    write(opReturn)
    writeIntLe(0) // nLockTime
  }.readByteString()
}

internal fun Buffer.writeCompactSize(value: Int): Buffer {
  require(value >= 0)
  when {
    value < 0xfd -> writeByte(value)
    value <= 0xffff -> {
      writeByte(0xfd)
      writeShortLe(value)
    }
    else -> {
      writeByte(0xfe)
      writeIntLe(value)
    }
  }
  return this
}
