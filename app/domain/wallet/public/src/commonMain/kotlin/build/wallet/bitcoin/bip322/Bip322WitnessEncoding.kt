package build.wallet.bitcoin.bip322

import okio.Buffer
import okio.ByteString
import okio.ByteString.Companion.toByteString

/**
 * Consensus-encode a Bitcoin witness stack and BIP-322 simple (`smp`) export.
 */
object Bip322WitnessEncoding {
  const val SIMPLE_PREFIX: String = "smp"

  fun encodeStack(elements: List<ByteString>): ByteString {
    return Buffer().apply {
      writeCompactSize(elements.size)
      for (element in elements) {
        writeCompactSize(element.size)
        write(element)
      }
    }.readByteString()
  }

  /** `smp` + base64(consensus-encoded witness stack). */
  fun exportSimple(elements: List<ByteString>): String =
    SIMPLE_PREFIX + encodeStack(elements).base64()
}

/**
 * Witness stack ECDSA signature: DER(sig) || sighash_type (default SIGHASH_ALL = 0x01).
 */
object WitnessEcdsaSignature {
  fun fromCompact(
    compact64: ByteString,
    sighashType: Byte = 0x01,
  ): ByteString {
    require(compact64.size == 64) { "compact ECDSA signature must be 64 bytes" }
    val der = compactEcdsaToDer(compact64)
    return Buffer().write(der).writeByte(sighashType.toInt()).readByteString()
  }
}

/**
 * Encode 64-byte compact (r||s) as BIP66 DER, forcing low-S.
 */
internal fun compactEcdsaToDer(compact64: ByteString): ByteString {
  require(compact64.size == 64)
  val r = compact64.substring(0, 32).toByteArray()
  var s = compact64.substring(32, 64).toByteArray()
  s = forceLowS(s)

  val rEnc = encodeDerInteger(r)
  val sEnc = encodeDerInteger(s)
  val bodyLen = 2 + rEnc.size + 2 + sEnc.size
  return Buffer()
    .writeByte(0x30)
    .writeByte(bodyLen)
    .writeByte(0x02)
    .writeByte(rEnc.size)
    .write(rEnc.toByteString())
    .writeByte(0x02)
    .writeByte(sEnc.size)
    .write(sEnc.toByteString())
    .readByteString()
}

private val SECP256K1_N =
  hexToBytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
private val SECP256K1_HALF_N =
  hexToBytes("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0")

private fun forceLowS(s: ByteArray): ByteArray {
  if (compareUnsigned(s, SECP256K1_HALF_N) <= 0) return s
  return subtract(SECP256K1_N, s)
}

private fun encodeDerInteger(raw32: ByteArray): ByteArray {
  var start = 0
  while (start < raw32.size - 1 && raw32[start] == 0.toByte()) {
    start++
  }
  var trimmed = raw32.copyOfRange(start, raw32.size)
  if (trimmed[0].toInt() and 0x80 != 0) {
    trimmed = byteArrayOf(0) + trimmed
  }
  return trimmed
}

private fun compareUnsigned(
  a: ByteArray,
  b: ByteArray,
): Int {
  require(a.size == b.size)
  for (i in a.indices) {
    val av = a[i].toInt() and 0xff
    val bv = b[i].toInt() and 0xff
    if (av != bv) return av - bv
  }
  return 0
}

private fun subtract(
  a: ByteArray,
  b: ByteArray,
): ByteArray {
  require(a.size == b.size)
  val out = ByteArray(a.size)
  var borrow = 0
  for (i in a.size - 1 downTo 0) {
    val diff = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff) - borrow
    if (diff < 0) {
      out[i] = (diff + 256).toByte()
      borrow = 1
    } else {
      out[i] = diff.toByte()
      borrow = 0
    }
  }
  require(borrow == 0)
  return out
}

private fun hexToBytes(hex: String): ByteArray {
  require(hex.length % 2 == 0)
  return ByteArray(hex.length / 2) { i ->
    hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
  }
}
