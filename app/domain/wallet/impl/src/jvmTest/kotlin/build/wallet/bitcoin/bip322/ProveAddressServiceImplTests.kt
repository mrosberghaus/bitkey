package build.wallet.bitcoin.bip322

import build.wallet.bdk.bindings.BdkKeychainKind
import build.wallet.bitcoin.BitcoinNetworkType
import build.wallet.bitcoin.address.BitcoinAddress
import build.wallet.encrypt.Secp256k1PublicKey
import build.wallet.testing.shouldBeOk
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.getOrThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldStartWith
import okio.ByteString.Companion.toByteString

class ProveAddressServiceImplTests : FunSpec({
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
  val path = SpendingChildPath(BdkKeychainKind.EXTERNAL, 7u)
  val message = ProveAddressMessage.create("prove this address").getOrThrow()
  val scriptPubKey = SortedMultiScript.p2wshScriptPubKey(script.witnessScript)
  val usedSpk = UsedScriptPubKey(
    network = BitcoinNetworkType.SIGNET,
    address = BitcoinAddress("tb1qexampleproveaddress000000000000000000000000"),
    scriptPubKey = scriptPubKey,
    path = path
  )

  val appSig = CompactEcdsaSignature.createOrThrow(ByteArray(64) { 1 }.toByteString())
  val hwSig = CompactEcdsaSignature.createOrThrow(ByteArray(64) { 2 }.toByteString())

  val appSigner = AppBip322SighashSigner { sighash, signedPath ->
    signedPath shouldBe path
    sighash.bytes.size shouldBe 32
    Ok(appSig)
  }
  val hwSigner = HwBip322SighashSigner { sighash, signedPath, signedAddress, signedMessage ->
    signedPath shouldBe path
    signedAddress shouldBe usedSpk.address
    signedMessage shouldBe message
    sighash.bytes.size shouldBe 32
    Ok(hwSig)
  }
  val resolver = SortedMultiScriptResolver { resolvedPath, expectedSpk ->
    resolvedPath shouldBe path
    expectedSpk shouldBe scriptPubKey
    Ok(script)
  }

  val service = ProveAddressServiceImpl(appSigner = appSigner, scriptResolver = resolver)

  test("prove exports smp prefix with non-empty witness and stable sighash") {
    val expectedChallenge = Bip322Challenge.create(usedSpk, message, script).getOrThrow()

    val proof = service.prove(usedSpk, message, hwSigner).shouldBeOk()
    val exported = proof.exportString()

    exported shouldStartWith "smp"
    exported.length shouldBeGreaterThan 8
    proof.address shouldBe usedSpk.address
    proof.message shouldBe message
    proof.witness.stack.size shouldBe 5
    proof.witness.stack[script.serverSlot + 1].size shouldBe 0
    proof.witness.stack[script.appSlot + 1].size shouldBeGreaterThan 0
    proof.witness.stack[script.hwSlot + 1].size shouldBeGreaterThan 0

    // Round-trip: same inputs rebuild the same challenge sighash the signers saw.
    val again = Bip322Challenge.create(usedSpk, message, script).getOrThrow()
    again.sighash shouldBe expectedChallenge.sighash
    again.toSpend shouldBe expectedChallenge.toSpend
    again.toSign shouldBe expectedChallenge.toSign
  }
})
