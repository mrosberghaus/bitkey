package build.wallet.bitcoin.attestation

import build.wallet.bdk.bindings.BdkKeychainKind
import build.wallet.bitcoin.BitcoinNetworkType
import build.wallet.bitcoin.address.BitcoinAddress
import com.github.michaelbull.result.getOrThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.encodeUtf8

class AddressAttestationChallengeTests : FunSpec({
  val address = BitcoinAddress("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
  val scriptPubKey = "0014751e76e8199196d454941c45d1b3a323f1433bd6".decodeHex()
  val message = AttestationMessage.create("prove ownership").getOrThrow()

  test("digest is stable for identical inputs") {
    val path = SpendingChildPath(BdkKeychainKind.EXTERNAL, 7u)
    val a = AddressAttestationChallenge.create(
      network = BitcoinNetworkType.SIGNET,
      address = address,
      scriptPubKey = scriptPubKey,
      path = path,
      message = message
    )
    val b = AddressAttestationChallenge.create(
      network = BitcoinNetworkType.SIGNET,
      address = address,
      scriptPubKey = scriptPubKey,
      path = path,
      message = message
    )

    a.digest shouldBe b.digest
    a.canonicalBytes shouldBe b.canonicalBytes
    a.digest.size shouldBe 32
  }

  test("digest changes when message changes") {
    val path = SpendingChildPath(BdkKeychainKind.EXTERNAL, 0u)
    val base = AddressAttestationChallenge.create(
      network = BitcoinNetworkType.SIGNET,
      address = address,
      scriptPubKey = scriptPubKey,
      path = path,
      message = message
    )
    val other = AddressAttestationChallenge.create(
      network = BitcoinNetworkType.SIGNET,
      address = address,
      scriptPubKey = scriptPubKey,
      path = path,
      message = AttestationMessage.create("different").getOrThrow()
    )

    other.digest shouldNotBe base.digest
  }

  test("digest changes when path changes") {
    val base = AddressAttestationChallenge.create(
      network = BitcoinNetworkType.SIGNET,
      address = address,
      scriptPubKey = scriptPubKey,
      path = SpendingChildPath(BdkKeychainKind.EXTERNAL, 0u),
      message = message
    )
    val other = AddressAttestationChallenge.create(
      network = BitcoinNetworkType.SIGNET,
      address = address,
      scriptPubKey = scriptPubKey,
      path = SpendingChildPath(BdkKeychainKind.INTERNAL, 0u),
      message = message
    )

    other.digest shouldNotBe base.digest
  }

  test("canonical bytes begin with length-prefixed tag") {
    val challenge = AddressAttestationChallenge.create(
      network = BitcoinNetworkType.BITCOIN,
      address = address,
      scriptPubKey = scriptPubKey,
      path = SpendingChildPath(BdkKeychainKind.EXTERNAL, 1u),
      message = message
    )
    val tag = AddressAttestationChallenge.TAG.encodeUtf8()
    challenge.canonicalBytes.substring(4, 4 + tag.size) shouldBe tag
  }
})
