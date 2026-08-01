package build.wallet.statemachine.addressattest

import build.wallet.bitkey.account.FullAccount
import build.wallet.statemachine.core.ScreenModel
import build.wallet.statemachine.core.StateMachine

/**
 * Settings flow to prove ownership of a used address via Bitkey-internal attestation.
 */
interface AddressAttestationUiStateMachine :
  StateMachine<AddressAttestationUiProps, ScreenModel>

data class AddressAttestationUiProps(
  val account: FullAccount,
  val onExit: () -> Unit,
)
