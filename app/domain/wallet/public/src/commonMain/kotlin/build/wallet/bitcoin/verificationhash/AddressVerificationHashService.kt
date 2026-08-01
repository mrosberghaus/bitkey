package build.wallet.bitcoin.verificationhash

import com.github.michaelbull.result.Result

interface AddressVerificationHashService {
  /**
   * App-sign + HW-sign a used scriptPubKey for [message], returning a verifiable verification hash.
   */
  suspend fun create(
    usedSpk: UsedScriptPubKey,
    message: VerificationMessage,
    hwSigner: HwVerificationHashSigner,
  ): Result<AddressVerificationHash, Error>
}
