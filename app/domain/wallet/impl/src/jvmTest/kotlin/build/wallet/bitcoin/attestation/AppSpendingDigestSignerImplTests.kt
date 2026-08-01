package build.wallet.bitcoin.attestation

import build.wallet.account.AccountServiceFake
import build.wallet.account.AccountStatus
import build.wallet.bdk.bindings.BdkKeychainKind
import build.wallet.bitcoin.AppPrivateKeyDaoFake
import build.wallet.bitcoin.BitcoinNetworkType
import build.wallet.bitcoin.address.BitcoinAddress
import build.wallet.bitcoin.keys.ExtendedPrivateKey
import build.wallet.bitkey.app.AppSpendingKeypair
import build.wallet.bitkey.app.AppSpendingPrivateKey
import build.wallet.bitkey.keybox.FullAccountMock
import build.wallet.bitkey.spending.AppSpendingPublicKeyMock
import build.wallet.bitkey.spending.SpendingKeysetMock
import build.wallet.encrypt.Secp256k1PublicKey
import build.wallet.testing.shouldBeOk
import build.wallet.toUByteList
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.getOrThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.toByteString
import uniffi.bdk.DerivationPath
import uniffi.bdk.DescriptorSecretKey
import uniffi.bdk.Mnemonic
import uniffi.bdk.Network
import build.wallet.rust.core.SecretKey as CoreSecretKey

class AppSpendingDigestSignerImplTests : FunSpec({
  val accountService = AccountServiceFake()
  val appPrivateKeyDao = AppPrivateKeyDaoFake()

  val mnemonic = Mnemonic.fromString(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  )
  val accountXprv = DescriptorSecretKey(Network.SIGNET, mnemonic, null)
    .derive(DerivationPath("m/84'/1'/0'"))
  val accountXprvString = accountXprv.toString()
  val appPublicKey = AppSpendingPublicKeyMock
  val appPrivateKey = AppSpendingPrivateKey(
    ExtendedPrivateKey(xprv = accountXprvString, mnemonic = mnemonic.toString())
  )

  val path = SpendingChildPath(BdkKeychainKind.EXTERNAL, 5u)
  val childSecret = accountXprv
    .derive(DerivationPath("m/${path.keychain.toChildNumber()}/${path.index}"))
    .secretBytes()
  val childPublicKey = Secp256k1PublicKey(
    CoreSecretKey(childSecret.toUByteList()).asPublic()
  )

  val account = FullAccountMock.copy(
    keybox = FullAccountMock.keybox.copy(
      activeSpendingKeyset = SpendingKeysetMock.copy(appKey = appPublicKey),
      keysets = listOf(SpendingKeysetMock.copy(appKey = appPublicKey))
    )
  )

  beforeTest {
    accountService.reset()
    appPrivateKeyDao.reset()
    accountService.accountState.value = Ok(AccountStatus.ActiveAccount(account))
    appPrivateKeyDao.storeAppSpendingKeyPair(
      AppSpendingKeypair(publicKey = appPublicKey, privateKey = appPrivateKey)
    )
  }

  val signer = AppSpendingDigestSignerImpl(accountService, appPrivateKeyDao)
  val ecdsa = AttestationEcdsaCryptoImpl()

  test("derive child, sign digest without rehash, verify compact signature") {
    val digest = ByteArray(32) { (it + 1).toByte() }.toByteString()

    val signature = signer.signDigest(digest, path).shouldBeOk()
    signature.bytes.size shouldBe 64

    ecdsa.verifyDigest(digest, signature, childPublicKey) shouldBe true

    val wrongDigest = ByteArray(32) { 0xAB.toByte() }.toByteString()
    ecdsa.verifyDigest(wrongDigest, signature, childPublicKey) shouldBe false
  }

  test("signDigest must not match a SHA-256-then-sign of the digest") {
    val digest = "11".repeat(32).decodeHex()
    val signature = signer.signDigest(digest, path).shouldBeOk()

    val rehashedSignature = CoreSecretKey(childSecret.toUByteList())
      .signMessage(digest.toUByteList())
    signature.bytes.hex() shouldNotBe rehashedSignature
  }

  test("AddressAttestationService attest with real app signer and fake HW") {
    val address = BitcoinAddress("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
    val scriptPubKey = "0014751e76e8199196d454941c45d1b3a323f1433bd6".decodeHex()
    val message = AttestationMessage.create("attest me").getOrThrow()
    val usedSpk = UsedScriptPubKey(
      network = BitcoinNetworkType.SIGNET,
      address = address,
      scriptPubKey = scriptPubKey,
      path = path
    )

    val hwSigner = HwAttestationSignerFake()
    val service = AddressAttestationServiceImpl(signer)
    val attestation = service.attest(usedSpk, message, hwSigner).shouldBeOk()

    ecdsa.verifyDigest(attestation.digest, attestation.appSignature, childPublicKey) shouldBe true
    ecdsa.verifyDigest(attestation.digest, attestation.hwSignature, childPublicKey) shouldBe false
  }

  test("reject wrong digest length") {
    val result = signer.signDigest(ByteArray(31).toByteString(), path)
    result.isErr shouldBe true
  }
})

private fun BdkKeychainKind.toChildNumber(): UInt =
  when (this) {
    BdkKeychainKind.EXTERNAL -> 0u
    BdkKeychainKind.INTERNAL -> 1u
  }
