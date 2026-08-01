package build.wallet.bitcoin.bip322

import build.wallet.encrypt.Secp256k1PublicKey
import com.github.michaelbull.result.getOrThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import okio.ByteString
import okio.ByteString.Companion.decodeHex

class SortedMultiWitnessAssembleTests : FunSpec({
  // Three distinct compressed pubkeys (BIP-322 P2WSH vector keys), labeled so BIP67
  // order is not the same as app/hw/server input order.
  val app = Secp256k1PublicKey(
    "030c529e0ea40a00975d202624e39915daf7bdd2b71f31aa08596838781ce5f33a"
  )
  val hw = Secp256k1PublicKey(
    "027568b11f122ff8a7bc1c57e5c7642055bc618967b2f7bfe8e11fe99903c94dd3"
  )
  val server = Secp256k1PublicKey(
    "020a8bdf79cfa421d9655e9282800f115ff1d9db1e721ceb4248a3fcfec7faa67c"
  )

  val script = SortedMultiScript.fromChildPubkeys(app = app, hw = hw, server = server).getOrThrow()

  test("fromChildPubkeys BIP67-orders keys and records role slots") {
    script.orderedPubkeys.map { it.value } shouldBe listOf(
      // 02... before 03...
      "020a8bdf79cfa421d9655e9282800f115ff1d9db1e721ceb4248a3fcfec7faa67c",
      "027568b11f122ff8a7bc1c57e5c7642055bc618967b2f7bfe8e11fe99903c94dd3",
      "030c529e0ea40a00975d202624e39915daf7bdd2b71f31aa08596838781ce5f33a"
    )
    script.serverSlot shouldBe 0
    script.hwSlot shouldBe 1
    script.appSlot shouldBe 2

    script.witnessScript.hex() shouldBe
      "5221020a8bdf79cfa421d9655e9282800f115ff1d9db1e721ceb4248a3fcfec7faa67c" +
      "21027568b11f122ff8a7bc1c57e5c7642055bc618967b2f7bfe8e11fe99903c94dd3" +
      "21030c529e0ea40a00975d202624e39915daf7bdd2b71f31aa08596838781ce5f33a53ae"
  }

  test("assemble places app/hw DER sigs in BIP67 slots and leaves server empty") {
    val appSig = "30".repeat(10).decodeHex()
    val hwSig = "30".repeat(11).decodeHex()

    val witness = SortedMultiWitness.assemble(script, appSig = appSig, hwSig = hwSig)

    witness.stack.size shouldBe 5
    witness.stack[0] shouldBe ByteString.EMPTY
    witness.stack[1] shouldBe ByteString.EMPTY // server slot 0
    witness.stack[2] shouldBe hwSig
    witness.stack[3] shouldBe appSig
    witness.stack[4] shouldBe script.witnessScript
  }
})
