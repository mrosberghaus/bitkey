package build.wallet.bitcoin.bip322

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import okio.Buffer
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.encodeUtf8

/**
 * Golden vectors from BIP-322 basic-test-vectors.json `tx_hashes`.
 */
class Bip322VirtualTransactionsTests : FunSpec({
  val scriptPubKey = "00142b05d564e6a7a33c087f16e0f730d1440123799d".decodeHex()

  data class Vector(
    val message: String,
    val messageHash: String,
    val toSpendTxHash: String,
    val toSignTxHash: String,
  )

  val vectors = listOf(
    Vector(
      message = "",
      messageHash = "c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1",
      toSpendTxHash = "c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7",
      toSignTxHash = "1e9654e951a5ba44c8604c4de6c67fd78a27e81dcadcfe1edf638ba3aaebaed6"
    ),
    Vector(
      message = "Hello World",
      messageHash = "f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a",
      toSpendTxHash = "b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b",
      toSignTxHash = "88737ae86f2077145f93cc4b153ae9a1cb8d56afa511988c149c5c8c9d93bddf"
    ),
    Vector(
      message = "UTF-8 support: öäüéàè 测试文本 \uD83D\uDE04",
      messageHash = "43936b237ea38c7794eb5d755e0d220b6db92ebfc5c8f482759d22b1286376d7",
      toSpendTxHash = "c8f4f525fe8afb1bc09b44175bd2096f079c98425e8a1be676b712add1fb62f0",
      toSignTxHash = "8f488e06b89eafd019ec528109eafaf7f1d1811fd617aa1eeb9658f1c1be6586"
    )
  )

  vectors.forEach { vector ->
    test("message_hash / to_spend / to_sign for ${vector.message.ifEmpty { "<empty>" }}") {
      val virtual = Bip322VirtualTransactions.create(
        message = vector.message.encodeUtf8(),
        scriptPubKey = scriptPubKey
      )

      virtual.messageHash.hex() shouldBe vector.messageHash
      virtual.toSpendTxid.hex() shouldBe vector.toSpendTxHash
      virtual.toSignTxid.hex() shouldBe vector.toSignTxHash
    }
  }

  test("segwit v0 SIGHASH_ALL is stable for empty-message P2WPKH vector") {
    val virtual = Bip322VirtualTransactions.create(
      message = "".encodeUtf8(),
      scriptPubKey = scriptPubKey
    )
    val scriptCode = Bip322SegwitV0Sighash.p2wpkhScriptCode(scriptPubKey)
    val sighash = Bip322SegwitV0Sighash.compute(virtual, scriptCode)

    sighash.bytes.hex() shouldBe "a3c9a960285a7e9320dae83b3be680c04e5599b3356d0f3fc11b82cb84ec4f0b"
  }

  test("segwit v0 SIGHASH_ALL for Hello World P2WPKH vector") {
    val virtual = Bip322VirtualTransactions.create(
      message = "Hello World".encodeUtf8(),
      scriptPubKey = scriptPubKey
    )
    val scriptCode = Bip322SegwitV0Sighash.p2wpkhScriptCode(scriptPubKey)
    val sighash = Bip322SegwitV0Sighash.compute(virtual, scriptCode)

    sighash.bytes.hex() shouldBe "af8a0cd31d9b0976e2aab2b82974c4388c4a3532b2ef828b96f14039ca372c14"
  }

  test("P2WSH 3-of-3 vector scriptPubKey and sighash are well-formed") {
    val witnessScript =
      "5321027568b11f122ff8a7bc1c57e5c7642055bc618967b2f7bfe8e11fe99903c94dd321020a8bdf79cfa421d9655e9282800f115ff1d9db1e721ceb4248a3fcfec7faa67c21030c529e0ea40a00975d202624e39915daf7bdd2b71f31aa08596838781ce5f33a53ae"
        .decodeHex()
    val spk = p2wshScriptPubKey(witnessScript)
    spk.size shouldBe 34
    spk[0] shouldBe 0x00.toByte()
    spk[1] shouldBe 0x20.toByte()
    spk.substring(2) shouldBe witnessScript.sha256()

    val virtual = Bip322VirtualTransactions.create(
      message = "This will be a p2wsh 3-of-3 multisig BIP 322 signed message".encodeUtf8(),
      scriptPubKey = spk
    )
    val sighash = Bip322SegwitV0Sighash.compute(
      virtual,
      Bip322SegwitV0Sighash.p2wshScriptCode(witnessScript)
    )
    sighash.bytes.size shouldBe 32
  }
})

private fun p2wshScriptPubKey(witnessScript: okio.ByteString): okio.ByteString {
  val program = witnessScript.sha256()
  return Buffer()
    .writeByte(0x00)
    .writeByte(0x20)
    .write(program)
    .readByteString()
}
