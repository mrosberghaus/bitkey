package build.wallet.bitcoin.verificationhash

import build.wallet.encrypt.Secp256k1PublicKey
import build.wallet.toByteString
import build.wallet.toUByteList
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import okio.ByteString.Companion.toByteString
import java.security.SecureRandom
import build.wallet.rust.core.SecretKey as CoreSecretKey

class VerificationHashEcdsaCryptoImplTests : FunSpec({
  val ecdsa = VerificationHashEcdsaCryptoImpl()

  fun randomKey(): Pair<CoreSecretKey, Secp256k1PublicKey> {
    val bytes = ByteArray(32)
    SecureRandom().nextBytes(bytes)
    val secret = CoreSecretKey(bytes.toUByteList())
    return secret to Secp256k1PublicKey(secret.asPublic())
  }

  test("verifyDigest accepts compact signature over prehashed digest") {
    val (secret, publicKey) = randomKey()
    val digest = ByteArray(32) { 7 }.toByteString()
    val signature = CompactEcdsaSignature.createOrThrow(
      secret.signDigest(digest.toUByteList()).toByteString()
    )

    ecdsa.verifyDigest(digest, signature, publicKey) shouldBe true
    ecdsa.verifyDigest(
      digest = ByteArray(32) { 8 }.toByteString(),
      signature = signature,
      publicKey = publicKey
    ) shouldBe false
    ecdsa.verifyDigest(
      digest = digest,
      signature = signature,
      publicKey = Secp256k1PublicKey("02" + "11".repeat(32))
    ) shouldBe false
  }

  test("verifyDigest rejects non-32-byte digest") {
    val (secret, publicKey) = randomKey()
    val digest = ByteArray(32) { 1 }.toByteString()
    val signature = CompactEcdsaSignature.createOrThrow(
      secret.signDigest(digest.toUByteList()).toByteString()
    )

    ecdsa.verifyDigest(ByteArray(16).toByteString(), signature, publicKey) shouldBe false
  }
})
