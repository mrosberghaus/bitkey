package build.wallet.nfc

import build.wallet.bitcoin.BitcoinNetworkType
import build.wallet.bitkey.hardware.HwSpendingPublicKey
import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import build.wallet.di.W3
import build.wallet.toByteString
import build.wallet.toUByteList
import okio.ByteString
import uniffi.bdk.DerivationPath
import uniffi.bdk.DescriptorSecretKey
import build.wallet.rust.core.SecretKey as CoreSecretKey

/** Fake HW: derive spending child and ECDSA-sign a prehashed 32-byte digest (no re-hash). */
@BitkeyInject(AppScope::class)
class FakeHwVerificationHashDigestSignerImpl(
  @W3 private val fakeHardwareKeyStore: FakeHardwareKeyStore,
) : FakeHwVerificationHashDigestSigner {
  override suspend fun sign(
    hwPublicKey: HwSpendingPublicKey,
    network: BitcoinNetworkType,
    change: UInt,
    addressIndex: UInt,
    digest: ByteString,
  ): ByteString {
    if (digest.size != 32) {
      throw NfcException.CommandError(message = "Attestation digest must be 32 bytes")
    }
    val accountPriv = fakeHardwareKeyStore.getSpendingPrivateKey(hwPublicKey, network)
    val childSecretBytes = DescriptorSecretKey.fromString(accountPriv.key.xprv)
      .derive(DerivationPath("m/$change/$addressIndex"))
      .secretBytes()
    return CoreSecretKey(childSecretBytes.toUByteList())
      .signDigest(digest.toUByteList())
      .toByteString()
  }
}
