package build.wallet.bitcoin.bip322

import build.wallet.account.AccountServiceFake
import build.wallet.account.AccountStatus
import build.wallet.bdk.bindings.BdkKeychainKind
import build.wallet.bitcoin.AppPrivateKeyDaoFake
import build.wallet.bitcoin.keys.ExtendedPrivateKey
import build.wallet.bitkey.app.AppSpendingKeypair
import build.wallet.bitkey.app.AppSpendingPrivateKey
import build.wallet.bitkey.keybox.FullAccountMock
import build.wallet.bitkey.spending.AppSpendingPublicKeyMock
import build.wallet.bitkey.spending.SpendingKeysetMock
import build.wallet.encrypt.Secp256k1PublicKey
import build.wallet.rust.core.SignatureVerifierException
import build.wallet.rust.core.verifyEcdsaDigest
import build.wallet.testing.shouldBeOk
import build.wallet.toUByteList
import com.github.michaelbull.result.Ok
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

class AppBip322SighashSignerImplTests : FunSpec({
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

  val signer = AppBip322SighashSignerImpl(accountService, appPrivateKeyDao)

  test("derive child, sign sighash without rehash, verify compact signature") {
    val sighash = Bip322Sighash.of(ByteArray(32) { (it + 1).toByte() }.toByteString())

    val signature = signer.sign(sighash, path).shouldBeOk()
    signature.bytes.size shouldBe 64

    verifyDigest(sighash.bytes.toByteArray(), signature, childPublicKey) shouldBe true

    val wrong = Bip322Sighash.of(ByteArray(32) { 0xAB.toByte() }.toByteString())
    verifyDigest(wrong.bytes.toByteArray(), signature, childPublicKey) shouldBe false
  }

  test("sign must not match a SHA-256-then-sign of the sighash") {
    val sighash = Bip322Sighash.of("11".repeat(32).decodeHex())
    val signature = signer.sign(sighash, path).shouldBeOk()

    val rehashedSignature = CoreSecretKey(childSecret.toUByteList())
      .signMessage(sighash.bytes.toUByteList())
    signature.bytes.hex() shouldNotBe rehashedSignature
  }

})

private fun verifyDigest(
  digest: ByteArray,
  signature: CompactEcdsaSignature,
  publicKey: Secp256k1PublicKey,
): Boolean =
  try {
    verifyEcdsaDigest(
      digest,
      signature.bytes.toUByteList(),
      publicKey.value.decodeHex().toByteArray()
    )
    true
  } catch (_: SignatureVerifierException) {
    false
  } catch (_: IllegalArgumentException) {
    false
  }

private fun BdkKeychainKind.toChildNumber(): UInt =
  when (this) {
    BdkKeychainKind.EXTERNAL -> 0u
    BdkKeychainKind.INTERNAL -> 1u
  }
