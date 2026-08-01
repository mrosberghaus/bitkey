package build.wallet.bitcoin.bip322

import build.wallet.bitcoin.address.BitcoinAddress
import com.github.michaelbull.result.Result

/**
 * Hardware seam: confirmable command shows [address] + [message], then signs [sighash].
 * Firmware must not treat this as a spend; display is message-prove UX.
 */
fun interface HwBip322SighashSigner {
  suspend fun sign(
    sighash: Bip322Sighash,
    path: SpendingChildPath,
    address: BitcoinAddress,
    message: ProveAddressMessage,
  ): Result<CompactEcdsaSignature, Error>
}
