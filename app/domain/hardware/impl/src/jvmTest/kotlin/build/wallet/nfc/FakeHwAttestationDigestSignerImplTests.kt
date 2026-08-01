package build.wallet.nfc

import build.wallet.bdk.legacy.BdkDescriptorSecretKeyGeneratorImpl
import build.wallet.bdk.legacy.BdkMnemonicGeneratorImpl
import build.wallet.bitcoin.BitcoinNetworkType.SIGNET
import build.wallet.bitkey.hardware.HwSpendingPublicKey
import build.wallet.encrypt.Secp256k1KeyGeneratorImpl
import build.wallet.store.EncryptedKeyValueStoreFactoryFake
import build.wallet.toByteString
import build.wallet.toUByteList
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import okio.ByteString.Companion.toByteString
import uniffi.bdk.DerivationPath
import uniffi.bdk.DescriptorSecretKey
import build.wallet.rust.core.SecretKey as CoreSecretKey

class FakeHwAttestationDigestSignerImplTests : FunSpec({
  val encryptedKeyValueStoreFactory = EncryptedKeyValueStoreFactoryFake()
  val fakeHardwareKeyStore =
    FakeHardwareKeyStoreImpl(
      BdkMnemonicGeneratorImpl(),
      BdkDescriptorSecretKeyGeneratorImpl(),
      Secp256k1KeyGeneratorImpl(),
      encryptedKeyValueStoreFactory
    )
  val signer = FakeHwAttestationDigestSignerImpl(fakeHardwareKeyStore)

  beforeTest {
    encryptedKeyValueStoreFactory.reset()
  }

  test("signs prehashed digest with HW spending child without re-hash") {
    val keypair = fakeHardwareKeyStore.getInitialSpendingKeypair(SIGNET)
    val hwPublicKey = HwSpendingPublicKey(keypair.publicKey.key)
    val change = 0u
    val addressIndex = 5u
    val digest = ByteArray(32) { (it + 3).toByte() }.toByteString()

    val signature = signer.sign(
      hwPublicKey = hwPublicKey,
      network = SIGNET,
      change = change,
      addressIndex = addressIndex,
      digest = digest
    )
    signature.size shouldBe 64

    val childSecret = DescriptorSecretKey.fromString(keypair.privateKey.key.xprv)
      .derive(DerivationPath("m/$change/$addressIndex"))
      .secretBytes()
    val expected = CoreSecretKey(childSecret.toUByteList())
      .signDigest(digest.toUByteList())
      .toByteString()
    signature shouldBe expected

    val rehashedHex = CoreSecretKey(childSecret.toUByteList())
      .signMessage(digest.toUByteList())
    signature.hex() shouldNotBe rehashedHex
  }
})
