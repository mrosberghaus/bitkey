package build.wallet.bitcoin.attestation

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

class AddressAttestationServiceImplTests : FunSpec({
  val address = BitcoinAddress("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
  val scriptPubKey = "0014751e76e8199196d454941c45d1b3a323f1433bd6".decodeHex()
  val path = SpendingChildPath(BdkKeychainKind.EXTERNAL, 1u)
  val message = AttestationMessage.create("attest me").getOrThrow()
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
  val hwSigner = HwAttestationSigner { digest, signedPath, signedAddress, signedMessage ->
    signedPath shouldBe path
    signedAddress shouldBe address
    signedMessage shouldBe message
    digest.size shouldBe 32
    Ok(hwSig)
  }

  val service = AddressAttestationServiceImpl(appSigner)

  test("attest assembles challenge digest with app and hw signatures") {
    val attestation = service.attest(usedSpk, message, hwSigner).shouldBeOk()

    val expected = AddressAttestationChallenge.create(
      network = usedSpk.network,
      address = usedSpk.address,
      scriptPubKey = usedSpk.scriptPubKey,
      path = usedSpk.path,
      message = message
    )
    attestation.digest shouldBe expected.digest
    attestation.appSignature shouldBe appSig
    attestation.hwSignature shouldBe hwSig
    attestation.address shouldBe address
    attestation.path shouldBe path
  }
})
