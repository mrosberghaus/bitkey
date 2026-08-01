package build.wallet.statemachine.proveaddress

import build.wallet.bitkey.account.FullAccount
import build.wallet.statemachine.core.ScreenModel
import build.wallet.statemachine.core.StateMachine

/**
 * Settings flow to prove ownership of a used address via BIP-322 simple signature.
 */
interface ProveAddressUiStateMachine : StateMachine<ProveAddressUiProps, ScreenModel>

data class ProveAddressUiProps(
  val account: FullAccount,
  val onExit: () -> Unit,
)
