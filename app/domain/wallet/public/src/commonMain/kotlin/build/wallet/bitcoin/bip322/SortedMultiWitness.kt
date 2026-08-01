package build.wallet.bitcoin.bip322

import okio.ByteString

/**
 * P2WSH sortedmulti witness stack for BIP-322 simple export.
 *
 * Stack: OP_0 empty | sig-or-empty × 3 (BIP67 order) | witnessScript.
 * Server slot stays empty for app+HW quorum.
 */
data class SortedMultiWitness(val stack: List<ByteString>) {
  init {
    require(stack.size == 5) {
      "sortedmulti(2-of-3) witness stack must be 5 elements, got ${stack.size}"
    }
  }

  companion object {
    fun assemble(
      script: SortedMultiScript,
      appSig: ByteString,
      hwSig: ByteString,
    ): SortedMultiWitness {
      require(appSig.size > 0) { "app witness signature must be non-empty" }
      require(hwSig.size > 0) { "hw witness signature must be non-empty" }

      val slots = arrayOf(ByteString.EMPTY, ByteString.EMPTY, ByteString.EMPTY)
      slots[script.appSlot] = appSig
      slots[script.hwSlot] = hwSig

      return SortedMultiWitness(
        listOf(ByteString.EMPTY) + slots.toList() + listOf(script.witnessScript)
      )
    }
  }
}
