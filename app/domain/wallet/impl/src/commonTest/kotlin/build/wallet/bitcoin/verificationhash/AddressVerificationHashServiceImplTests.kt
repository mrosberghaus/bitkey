package build.wallet.bitcoin.verificationhash

import build.wallet.bdk.bindings.BdkKeychainKind
import build.wallet.bitcoin.BitcoinNetworkType
import build.wallet.bitcoin.address.BitcoinAddress
import build.wallet.testing.shouldBeOk
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.getOrThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.toByteString

class AddressVerificationHashServiceImplTests : FunSpec({
  val address = BitcoinAddress("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
  val scriptPubKey = "0014751e76e8199196d454941c45d1b3a323f1433bd6".decodeHex()
  val path = SpendingChildPath(BdkKeychainKind.EXTERNAL, 1u)
  val message = VerificationMessage.create("prove me").getOrThrow()
  val usedSpk = UsedScriptPubKey(
    network = BitcoinNetworkType.SIGNET,
    address = address,
    scriptPubKey = scriptPubKey,
    path = path
  )

  val appSig = CompactEcdsaSignature.createOrThrow(ByteArray(64) { 1 }.toByteString())
  val hwSig = CompactEcdsaSignature.createOrThrow(ByteArray(64) { 2 }.toByteString())

  val appSigner = AppSpendingDigestSigner { digest, signedPath ->
    signedPath shouldBe path
    digest.size shouldBe 32
    Ok(appSig)
  }
  val hwSigner = HwVerificationHashSigner { digest, signedPath, signedAddress, signedMessage ->
    signedPath shouldBe path
    signedAddress shouldBe address
    signedMessage shouldBe message
    digest.size shouldBe 32
    Ok(hwSig)
  }

  val service = AddressVerificationHashServiceImpl(appSigner)

  test("create assembles challenge digest with app and hw signatures") {
    val verificationHash = service.create(usedSpk, message, hwSigner).shouldBeOk()

    val expected = AddressVerificationChallenge.create(
      network = usedSpk.network,
      address = usedSpk.address,
      scriptPubKey = usedSpk.scriptPubKey,
      path = usedSpk.path,
      message = message
    )
    verificationHash.digest shouldBe expected.digest
    verificationHash.appSignature shouldBe appSig
    verificationHash.hwSignature shouldBe hwSig
    verificationHash.address shouldBe address
    verificationHash.path shouldBe path
  }
})
