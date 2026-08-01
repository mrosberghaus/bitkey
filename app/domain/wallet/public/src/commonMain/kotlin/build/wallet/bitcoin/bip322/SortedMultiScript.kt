package build.wallet.bitcoin.bip322

import build.wallet.encrypt.Secp256k1PublicKey
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import okio.Buffer
import okio.ByteString
import okio.ByteString.Companion.decodeHex

/**
 * BIP67-ordered keys and redeem script for one `wsh(sortedmulti(2,app,hw,server))` address index.
 * Single source of truth for witness slot placement.
 */
data class SortedMultiScript(
  /** Exactly three compressed pubkeys, sorted ascending per BIP67. */
  val orderedPubkeys: List<Secp256k1PublicKey>,
  /** Witness script: OP_2 <k0> <k1> <k2> OP_3 OP_CHECKMULTISIG */
  val witnessScript: ByteString,
  /** Which ordered slots are app / hw (server is the remaining empty slot). */
  val appSlot: Int,
  val hwSlot: Int,
) {
  init {
    require(orderedPubkeys.size == 3) { "sortedmulti(2-of-3) needs 3 keys" }
    require(appSlot in 0..2 && hwSlot in 0..2 && appSlot != hwSlot) {
      "appSlot and hwSlot must be distinct indices in 0..2"
    }
  }

  val serverSlot: Int
    get() = (0..2).first { it != appSlot && it != hwSlot }

  companion object {
    /**
     * BIP67-sort [app]/[hw]/[server] compressed pubkeys and build the 2-of-3 witness script.
     */
    fun fromChildPubkeys(
      app: Secp256k1PublicKey,
      hw: Secp256k1PublicKey,
      server: Secp256k1PublicKey,
    ): Result<SortedMultiScript, Error> {
      val labeled = listOf(
        Role.App to parseCompressed(app),
        Role.Hw to parseCompressed(hw),
        Role.Server to parseCompressed(server)
      )
      val distinct = labeled.map { it.second.hex() }.toSet()
      if (distinct.size != 3) {
        return Err(Error("sortedmulti keys must be three distinct compressed pubkeys"))
      }

      val ordered = labeled.sortedWith { a, b -> compareUnsigned(a.second, b.second) }
      val orderedKeys = ordered.map { (_, bytes) -> Secp256k1PublicKey(bytes.hex()) }
      val appSlot = ordered.indexOfFirst { it.first == Role.App }
      val hwSlot = ordered.indexOfFirst { it.first == Role.Hw }
      val witnessScript = encodeWitnessScript(ordered.map { it.second })
      return Ok(
        SortedMultiScript(
          orderedPubkeys = orderedKeys,
          witnessScript = witnessScript,
          appSlot = appSlot,
          hwSlot = hwSlot
        )
      )
    }

    fun p2wshScriptPubKey(witnessScript: ByteString): ByteString =
      Buffer()
        .writeByte(0x00)
        .writeByte(0x20)
        .write(witnessScript.sha256())
        .readByteString()
  }
}

private enum class Role { App, Hw, Server }

private fun parseCompressed(key: Secp256k1PublicKey): ByteString {
  val bytes = key.value.decodeHex()
  require(bytes.size == 33) { "compressed pubkey must be 33 bytes, got ${bytes.size}" }
  require(bytes[0] == 0x02.toByte() || bytes[0] == 0x03.toByte()) {
    "compressed pubkey must start with 02 or 03"
  }
  return bytes
}

private fun encodeWitnessScript(orderedCompressed: List<ByteString>): ByteString {
  require(orderedCompressed.size == 3)
  return Buffer().apply {
    writeByte(0x52) // OP_2
    for (key in orderedCompressed) {
      writeByte(0x21) // PUSH33
      write(key)
    }
    writeByte(0x53) // OP_3
    writeByte(0xae) // OP_CHECKMULTISIG
  }.readByteString()
}

private fun compareUnsigned(
  a: ByteString,
  b: ByteString,
): Int {
  val len = minOf(a.size, b.size)
  for (i in 0 until len) {
    val av = a[i].toInt() and 0xff
    val bv = b[i].toInt() and 0xff
    if (av != bv) return av - bv
  }
  return a.size - b.size
}
