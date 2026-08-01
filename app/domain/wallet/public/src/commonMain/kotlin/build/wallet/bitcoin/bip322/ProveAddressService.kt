package build.wallet.bitcoin.bip322

import build.wallet.bitcoin.verificationhash.UsedScriptPubKey
import com.github.michaelbull.result.Result

/**
 * Single entry for Settings Prove address.
 * Hides virtual txs, sighash, app/HW sign, witness assembly, smp export.
 */
interface ProveAddressService {
  suspend fun prove(
    usedSpk: UsedScriptPubKey,
    message: ProveAddressMessage,
    hwSigner: HwBip322SighashSigner,
  ): Result<Bip322SimpleProof, Error>
}
