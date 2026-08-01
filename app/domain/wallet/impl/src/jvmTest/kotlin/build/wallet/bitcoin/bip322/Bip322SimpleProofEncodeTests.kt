package build.wallet.bitcoin.bip322

import build.wallet.rust.core.verifyEcdsaDigest
import build.wallet.toByteString
import build.wallet.toUByteList
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldStartWith
import okio.Buffer
import okio.ByteString
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.encodeUtf8
import build.wallet.rust.core.SecretKey as CoreSecretKey

/**
 * Sign + export BIP-322 simple proofs for BIP basic-test-vectors using test keys.
 */
class Bip322SimpleProofEncodeTests : FunSpec({
  val p2wpkhScriptPubKey = "00142b05d564e6a7a33c087f16e0f730d1440123799d".decodeHex()
  val p2wpkhPriv = "bb051cd0dda0246f33c5a9e133ebd8e7bc02a92af6c41adc131ccd7826c5b004".decodeHex()
  val p2wpkhPub = "02c7f12003196442943d8588e01aee840423cc54fc1521526a3b85c2b0cbd58872".decodeHex()

  val emptyMessageSignatures = listOf(
    "smpAkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
    "smpAkgwRQIhAPkJ1Q4oYS0htvyuSFHLxRQpFAY56b70UvE7Dxazen0ZAiAtZfFz1S6T6I23MWI2lK/pcNTWncuyL8UL+oMdydVgzAEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy"
  )

  val helloWorldSignatures = listOf(
    "smpAkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
    "smpAkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy"
  )

  test("P2WPKH empty message: sign sighash, export smp matching BIP vector") {
    val virtual = Bip322VirtualTransactions.create("".encodeUtf8(), p2wpkhScriptPubKey)
    val scriptCode = Bip322SegwitV0Sighash.p2wpkhScriptCode(p2wpkhScriptPubKey)
    val sighash = Bip322SegwitV0Sighash.compute(virtual, scriptCode)

    val secret = CoreSecretKey(p2wpkhPriv.toUByteList())
    secret.asPublic() shouldBe p2wpkhPub.hex()

    val compact = secret.signDigest(sighash.bytes.toUByteList()).toByteString()
    verifyEcdsaDigest(
      sighash.bytes.toByteArray(),
      compact.toUByteList(),
      p2wpkhPub.toByteArray()
    )

    val witnessSig = WitnessEcdsaSignature.fromCompact(compact)
    val smp = Bip322WitnessEncoding.exportSimple(listOf(witnessSig, p2wpkhPub))

    smp shouldStartWith "smp"
    emptyMessageSignatures shouldContain smp
  }

  test("P2WPKH Hello World: export smp matching BIP vector") {
    val virtual = Bip322VirtualTransactions.create("Hello World".encodeUtf8(), p2wpkhScriptPubKey)
    val sighash = Bip322SegwitV0Sighash.compute(
      virtual,
      Bip322SegwitV0Sighash.p2wpkhScriptCode(p2wpkhScriptPubKey)
    )
    val compact = CoreSecretKey(p2wpkhPriv.toUByteList())
      .signDigest(sighash.bytes.toUByteList())
      .toByteString()
    val smp = Bip322WitnessEncoding.exportSimple(
      listOf(WitnessEcdsaSignature.fromCompact(compact), p2wpkhPub)
    )
    helloWorldSignatures shouldContain smp
  }

  test("P2WSH 3-of-3: sign all keys in script order and export smp matching BIP vector") {
    val message = "This will be a p2wsh 3-of-3 multisig BIP 322 signed message".encodeUtf8()
    val witnessScript =
      "5321027568b11f122ff8a7bc1c57e5c7642055bc618967b2f7bfe8e11fe99903c94dd321020a8bdf79cfa421d9655e9282800f115ff1d9db1e721ceb4248a3fcfec7faa67c21030c529e0ea40a00975d202624e39915daf7bdd2b71f31aa08596838781ce5f33a53ae"
        .decodeHex()
    val scriptPubKey = Buffer()
      .writeByte(0x00)
      .writeByte(0x20)
      .write(witnessScript.sha256())
      .readByteString()

    val orderedPubkeys = listOf(
      "027568b11f122ff8a7bc1c57e5c7642055bc618967b2f7bfe8e11fe99903c94dd3",
      "020a8bdf79cfa421d9655e9282800f115ff1d9db1e721ceb4248a3fcfec7faa67c",
      "030c529e0ea40a00975d202624e39915daf7bdd2b71f31aa08596838781ce5f33a"
    )

    // WIF-decoded secrets from basic-test-vectors.json; map into witness-script pubkey order.
    val secretsByPub = listOf(
      "d0e2b87bb15981581da8639f5e4c91ffe027c4d532b282ad829744c3dc15abf5",
      "600e0fc98be726c8f50a22c095686cf919e656e7ae5fb01edf0739df164e6c45",
      "8e966ffb1dbf7126a2e2cf545842e3bfdfaa924dfe9ce4d16abd02adba3dfc53"
    ).associate { hex ->
      val secret = CoreSecretKey(hex.decodeHex().toUByteList())
      secret.asPublic() to secret
    }

    orderedPubkeys.forEach { pub ->
      secretsByPub.containsKey(pub) shouldBe true
    }

    val virtual = Bip322VirtualTransactions.create(message, scriptPubKey)
    val sighash = Bip322SegwitV0Sighash.compute(
      virtual,
      Bip322SegwitV0Sighash.p2wshScriptCode(witnessScript)
    )

    val sigs = orderedPubkeys.map { pub ->
      val compact = secretsByPub.getValue(pub)
        .signDigest(sighash.bytes.toUByteList())
        .toByteString()
      WitnessEcdsaSignature.fromCompact(compact)
    }

    val stack = listOf(ByteString.EMPTY) + sigs + listOf(witnessScript)
    val smp = Bip322WitnessEncoding.exportSimple(stack)

    smp shouldBe
      "smpBQBHMEQCIFX9aaqPJWq2Ff2kpen5bFDTid+ehgUOpHV0LfjncXy4AiA3GNicF7aKPzdpa9PCpmaYQs3pHd+qbvvhXdxOCKCAMAFIMEUCIQD/ELXg6CNYyUQijCg96JtgvgjZb9dsl1Ctof4QAeyTcQIgVM/1AAblFl/DCt6A1gJg+T/i2qU5SQD09+chFJzolRwBSDBFAiEAlqRfSFyWNVQhvaCnmeV5tyneiCWMTcFbuujoD/pFa3wCIGnZjfQb8NolSYq9asV+ZeBSkCGHJcqnaV4JYS5MYPEGAWlTIQJ1aLEfEi/4p7wcV+XHZCBVvGGJZ7L3v+jhH+mZA8lN0yECCovfec+kIdllXpKCgA8RX/HZ2x5yHOtCSKP8/sf6pnwhAwxSng6kCgCXXSAmJOOZFdr3vdK3HzGqCFloOHgc5fM6U64="
  }
})
