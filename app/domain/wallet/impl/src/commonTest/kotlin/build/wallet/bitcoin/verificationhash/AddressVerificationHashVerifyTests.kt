package build.wallet.bitcoin.verificationhash

import build.wallet.bdk.bindings.BdkKeychainKind
import build.wallet.bitcoin.BitcoinNetworkType
import build.wallet.bitcoin.address.BitcoinAddress
import build.wallet.encrypt.Secp256k1PublicKey
import com.github.michaelbull.result.getOrThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.toByteString

class AddressVerificationHashVerifyTests : FunSpec({
  val address = BitcoinAddress("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
  val scriptPubKey = "0014751e76e8199196d454941c45d1b3a323f1433bd6".decodeHex()
  val path = SpendingChildPath(BdkKeychainKind.EXTERNAL, 3u)
  val message = VerificationMessage.create("hello bitkey").getOrThrow()
  val appPub = Secp256k1PublicKey("02" + "11".repeat(32))
  val hwPub = Secp256k1PublicKey("03" + "22".repeat(32))
  val appSig = CompactEcdsaSignature.createOrThrow(ByteArray(64) { 0xA1.toByte() }.toByteString())
  val hwSig = CompactEcdsaSignature.createOrThrow(ByteArray(64) { 0xB2.toByte() }.toByteString())

  val challenge = AddressVerificationChallenge.create(
    network = BitcoinNetworkType.SIGNET,
    address = address,
    scriptPubKey = scriptPubKey,
    path = path,
    message = message
  )

  val verificationHash = AddressVerificationHash(
    version = challenge.version,
    network = challenge.network,
    address = challenge.address,
    scriptPubKey = challenge.scriptPubKey,
    path = challenge.path,
    message = challenge.message,
    digest = challenge.digest,
    appSignature = appSig,
    hwSignature = hwSig
  )

  val watchingExternal = WatchingVerificationKeychain.of(
    addresses = mapOf(3u to address),
    scriptPubKeys = mapOf(3u to scriptPubKey),
    appPublicKeys = mapOf(3u to appPub),
    hwPublicKeys = mapOf(3u to hwPub)
  )
  val watchingInternal = WatchingVerificationKeychain.of()

  val acceptingEcdsa = VerificationHashEcdsaCrypto { digest, signature, publicKey ->
    digest == challenge.digest &&
      (
        (signature == appSig && publicKey == appPub) ||
          (signature == hwSig && publicKey == hwPub)
      )
  }

  test("verify happy path with two known signatures") {
    val result = AddressVerificationHash.verify(
      verificationHash = verificationHash,
      watchingExternal = watchingExternal,
      watchingInternal = watchingInternal,
      ecdsa = acceptingEcdsa
    )
    result shouldBe AddressVerificationHashResult.Valid
  }

  test("reject wrong message") {
    val wrongMessage = VerificationMessage.create("tampered").getOrThrow()
    val wrong = verificationHash.copy(message = wrongMessage)
    val result = AddressVerificationHash.verify(
      verificationHash = wrong,
      watchingExternal = watchingExternal,
      watchingInternal = watchingInternal,
      ecdsa = acceptingEcdsa
    ).shouldBeInstanceOf<AddressVerificationHashResult.Invalid>()

    result.reasons shouldContain AddressVerificationHashInvalidReason.DigestMismatch
  }

  test("reject wrong path") {
    val wrongPath = SpendingChildPath(BdkKeychainKind.INTERNAL, 3u)
    val wrong = verificationHash.copy(path = wrongPath)
    val result = AddressVerificationHash.verify(
      verificationHash = wrong,
      watchingExternal = watchingExternal,
      watchingInternal = watchingInternal,
      ecdsa = acceptingEcdsa
    ).shouldBeInstanceOf<AddressVerificationHashResult.Invalid>()

    result.reasons shouldContain AddressVerificationHashInvalidReason.AddressMismatch
    result.reasons shouldContain AddressVerificationHashInvalidReason.ScriptPubKeyMismatch
  }

  test("reject invalid app signature") {
    val rejectingApp = VerificationHashEcdsaCrypto { _, signature, publicKey ->
      !(signature == appSig && publicKey == appPub)
    }
    val result = AddressVerificationHash.verify(
      verificationHash = verificationHash,
      watchingExternal = watchingExternal,
      watchingInternal = watchingInternal,
      ecdsa = rejectingApp
    ).shouldBeInstanceOf<AddressVerificationHashResult.Invalid>()

    result.reasons shouldContain AddressVerificationHashInvalidReason.InvalidAppSignature
  }

  test("encode decode round trip") {
    val encoded = verificationHash.encode()
    val decoded = AddressVerificationHash.decode(encoded).getOrThrow()
    decoded shouldBe verificationHash
  }
})
