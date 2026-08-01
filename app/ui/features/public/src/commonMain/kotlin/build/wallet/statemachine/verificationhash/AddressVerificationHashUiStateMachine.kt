package build.wallet.statemachine.verificationhash

import build.wallet.bitkey.account.FullAccount
import build.wallet.statemachine.core.ScreenModel
import build.wallet.statemachine.core.StateMachine

/**
 * Settings flow to prove ownership of a used address via Bitkey-internal verificationHash.
 */
interface AddressVerificationHashUiStateMachine :
  StateMachine<AddressVerificationHashUiProps, ScreenModel>

data class AddressVerificationHashUiProps(
  val account: FullAccount,
  val onExit: () -> Unit,
)
