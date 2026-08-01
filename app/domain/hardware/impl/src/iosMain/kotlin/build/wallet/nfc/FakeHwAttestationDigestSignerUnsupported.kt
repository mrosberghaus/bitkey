package build.wallet.nfc

import build.wallet.bitcoin.BitcoinNetworkType
import build.wallet.bitkey.hardware.HwSpendingPublicKey
import build.wallet.di.AppScope
import build.wallet.di.BitkeyInject
import okio.ByteString

@BitkeyInject(AppScope::class)
class FakeHwAttestationDigestSignerUnsupported : FakeHwAttestationDigestSigner {
  override suspend fun sign(
    hwPublicKey: HwSpendingPublicKey,
    network: BitcoinNetworkType,
    change: UInt,
    addressIndex: UInt,
    digest: ByteString,
  ): ByteString = throw NfcException.FeatureNotSupported()
}
