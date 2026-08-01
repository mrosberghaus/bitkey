package build.wallet.bitcoin.bip322

import okio.Buffer
import okio.ByteString
import okio.ByteString.Companion.toByteString

/**
 * 32-byte BIP-322 / BIP143 segwit v0 sighash for to_sign input 0.
 */
data class Bip322Sighash private constructor(val bytes: ByteString) {
  init {
    require(bytes.size == 32) { "BIP-322 sighash must be 32 bytes" }
  }

  companion object {
    fun of(bytes: ByteString): Bip322Sighash {
      require(bytes.size == 32) { "BIP-322 sighash must be 32 bytes" }
      return Bip322Sighash(bytes)
    }
  }
}

/**
 * Segwit v0 SIGHASH_ALL over BIP-322 [Bip322VirtualTransactions.toSign] input 0.
 *
 * Amount is always 0 (virtual to_spend output). [scriptCode] is BIP143 scriptCode:
 * P2WPKH uses the classic P2PKH script; P2WSH uses the witness script itself.
 */
object Bip322SegwitV0Sighash {
  const val SIGHASH_ALL: Int = 1

  fun compute(
    virtual: Bip322VirtualTransactions,
    scriptCode: ByteString,
  ): Bip322Sighash {
    val toSpendTxidInternal = virtual.toSpendTxid.reversedBytes()
    val hashPrevouts = hash256(
      Buffer()
        .write(toSpendTxidInternal)
        .writeIntLe(0)
        .readByteString()
    )
    val hashSequence = hash256(Buffer().writeIntLe(0).readByteString())
    val opReturn = byteArrayOf(0x6a).toByteString()
    val hashOutputs = hash256(
      Buffer()
        .writeLongLe(0)
        .writeCompactSize(opReturn.size)
        .write(opReturn)
        .readByteString()
    )

    val preimage = Buffer().apply {
      writeIntLe(0) // nVersion of to_sign
      write(hashPrevouts)
      write(hashSequence)
      write(toSpendTxidInternal)
      writeIntLe(0) // outpoint index
      writeCompactSize(scriptCode.size)
      write(scriptCode)
      writeLongLe(0) // amount
      writeIntLe(0) // nSequence
      write(hashOutputs)
      writeIntLe(0) // nLockTime
      writeIntLe(SIGHASH_ALL)
    }.readByteString()

    return Bip322Sighash.of(hash256(preimage))
  }

  /**
   * BIP143 scriptCode for a P2WPKH scriptPubKey (`0014` || 20-byte hash).
   */
  fun p2wpkhScriptCode(scriptPubKey: ByteString): ByteString {
    require(scriptPubKey.size == 22) {
      "P2WPKH scriptPubKey must be 22 bytes, got ${scriptPubKey.size}"
    }
    require(scriptPubKey[0] == 0x00.toByte() && scriptPubKey[1] == 0x14.toByte()) {
      "P2WPKH scriptPubKey must start with 0014"
    }
    val hash160 = scriptPubKey.substring(2, 22)
    return Buffer()
      .writeByte(0x76) // OP_DUP
      .writeByte(0xa9) // OP_HASH160
      .writeByte(0x14)
      .write(hash160)
      .writeByte(0x88) // OP_EQUALVERIFY
      .writeByte(0xac) // OP_CHECKSIG
      .readByteString()
  }

  /** BIP143 scriptCode for P2WSH is the witness script itself. */
  fun p2wshScriptCode(witnessScript: ByteString): ByteString = witnessScript
}
