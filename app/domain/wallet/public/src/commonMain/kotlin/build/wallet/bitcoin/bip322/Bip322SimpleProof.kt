package build.wallet.bitcoin.bip322

import build.wallet.bitcoin.address.BitcoinAddress

/**
 * Shareable BIP-322 simple proof. Only public export form in v1.
 */
data class Bip322SimpleProof(
  val address: BitcoinAddress,
  val message: ProveAddressMessage,
  val witness: SortedMultiWitness,
) {
  /** `smp` + base64(consensus-encoded witness stack of to_sign vin[0]). */
  fun exportString(): String = Bip322WitnessEncoding.exportSimple(witness.stack)
}
