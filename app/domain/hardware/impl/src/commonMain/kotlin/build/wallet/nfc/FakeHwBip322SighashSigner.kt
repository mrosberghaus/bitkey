package build.wallet.nfc

import build.wallet.bitcoin.BitcoinNetworkType
import build.wallet.bitkey.hardware.HwSpendingPublicKey
import okio.ByteString

/**
 * Fake-hardware helper: derive HW spending child and ECDSA-sign a 32-byte digest
 * (no extra hash). Real firmware performs the same operation on-device.
 */
fun interface FakeHwBip322SighashSigner {
  suspend fun sign(
    hwPublicKey: HwSpendingPublicKey,
    network: BitcoinNetworkType,
    change: UInt,
    addressIndex: UInt,
    digest: ByteString,
  ): ByteString
}
