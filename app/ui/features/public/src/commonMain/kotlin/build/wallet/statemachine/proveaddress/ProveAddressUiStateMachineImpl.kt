package build.wallet.statemachine.proveaddress

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import build.wallet.analytics.events.screen.context.NfcEventTrackerScreenIdContext
import build.wallet.analytics.events.screen.id.ProveAddressEventTrackerScreenId
import build.wallet.bdk.bindings.BdkKeychainKind
import build.wallet.bitcoin.bip322.Bip322Challenge
import build.wallet.bitcoin.bip322.Bip322SimpleProof
import build.wallet.bitcoin.bip322.CompactEcdsaSignature
import build.wallet.bitcoin.bip322.HwBip322SighashSigner
import build.wallet.bitcoin.bip322.ProveAddressMessage
import build.wallet.bitcoin.bip322.ProveAddressMessageError
import build.wallet.bitcoin.bip322.ProveAddressService
import build.wallet.bitcoin.bip322.SortedMultiScriptResolver
import build.wallet.bitcoin.bip322.UsedScriptPubKey
import build.wallet.bitcoin.transactions.BitcoinWalletService
import build.wallet.di.ActivityScope
import build.wallet.di.BitkeyInject
import build.wallet.logging.logFailure
import build.wallet.platform.clipboard.ClipItem.PlainText
import build.wallet.platform.clipboard.Clipboard
import build.wallet.platform.sharing.SharingManager
import build.wallet.statemachine.core.ButtonDataModel
import build.wallet.statemachine.core.ErrorData
import build.wallet.statemachine.core.ErrorFormBodyModel
import build.wallet.statemachine.core.LoadingSuccessBodyModel
import build.wallet.statemachine.core.LoadingSuccessBodyModel.State.Loading
import build.wallet.statemachine.core.ScreenModel
import build.wallet.statemachine.core.ScreenPresentationStyle
import build.wallet.statemachine.nfc.ConfirmationResultContent
import build.wallet.statemachine.nfc.NfcConfirmableSessionUIStateMachineProps
import build.wallet.statemachine.nfc.NfcConfirmableSessionUiStateMachine
import build.wallet.statemachine.proveaddress.ProveAddressUiStateMachineImpl.State.ConfirmOnHardware
import build.wallet.statemachine.proveaddress.ProveAddressUiStateMachineImpl.State.Done
import build.wallet.statemachine.proveaddress.ProveAddressUiStateMachineImpl.State.EnterMessage
import build.wallet.statemachine.proveaddress.ProveAddressUiStateMachineImpl.State.LoadingUsedAddresses
import build.wallet.statemachine.proveaddress.ProveAddressUiStateMachineImpl.State.NoUsedAddresses
import build.wallet.statemachine.proveaddress.ProveAddressUiStateMachineImpl.State.SelectUsedAddress
import build.wallet.statemachine.proveaddress.ProveAddressUiStateMachineImpl.State.ShowingError
import build.wallet.statemachine.send.hardwareconfirmation.HardwareConfirmationContent
import build.wallet.statemachine.settings.SettingsAppSegment
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.get
import com.github.michaelbull.result.getError
import com.github.michaelbull.result.getOrThrow
import com.github.michaelbull.result.onFailure
import com.github.michaelbull.result.onSuccess
import kotlinx.coroutines.launch
import okio.ByteString

@BitkeyInject(ActivityScope::class)
class ProveAddressUiStateMachineImpl(
  private val bitcoinWalletService: BitcoinWalletService,
  private val proveAddressService: ProveAddressService,
  private val sortedMultiScriptResolver: SortedMultiScriptResolver,
  private val nfcConfirmableSessionUiStateMachine: NfcConfirmableSessionUiStateMachine,
  private val sharingManager: SharingManager,
  private val clipboard: Clipboard,
) : ProveAddressUiStateMachine {
  @Composable
  override fun model(props: ProveAddressUiProps): ScreenModel {
    var state: State by remember { mutableStateOf(LoadingUsedAddresses) }

    return when (val current = state) {
      is LoadingUsedAddresses -> {
        LaunchedEffect("load-used-script-pubkeys") {
          val wallet = bitcoinWalletService.spendingWallet().value
          if (wallet == null) {
            state = ShowingError(
              cause = Error("No active spending wallet"),
              retry = LoadingUsedAddresses
            )
            return@LaunchedEffect
          }
          wallet.listUsedScriptPubKeys()
            .logFailure { "Failed to list used scriptPubKeys for prove address" }
            .onSuccess { used ->
              state = if (used.isEmpty()) {
                NoUsedAddresses
              } else {
                SelectUsedAddress(used)
              }
            }
            .onFailure { error ->
              state = ShowingError(cause = error, retry = LoadingUsedAddresses)
            }
        }
        LoadingSuccessBodyModel(
          onBack = props.onExit,
          state = Loading,
          id = ProveAddressEventTrackerScreenId.LOADING_USED_ADDRESSES
        ).asRootScreen()
      }

      is NoUsedAddresses -> ErrorFormBodyModel(
        title = "No used addresses",
        subline = "Receive or send bitcoin first, then try again.",
        primaryButton = ButtonDataModel(text = "OK", onClick = props.onExit),
        onBack = props.onExit,
        eventTrackerScreenId = ProveAddressEventTrackerScreenId.NO_USED_ADDRESSES,
        errorData = ErrorData(
          segment = SettingsAppSegment.ProveAddress,
          actionDescription = "Listing used addresses for prove address",
          cause = Error("No used scriptPubKeys")
        )
      ).asRootScreen()

      is SelectUsedAddress -> SelectUsedAddressBodyModel(
        onBack = props.onExit,
        usedAddresses = current.addresses,
        onAddressSelected = { usedSpk ->
          state = EnterMessage(
            addresses = current.addresses,
            usedSpk = usedSpk,
            draft = ""
          )
        }
      ).asRootScreen()

      is EnterMessage -> {
        val validationError = messageValidationError(current.draft)
        EnterProveAddressMessageBodyModel(
          onBack = {
            state = SelectUsedAddress(current.addresses)
          },
          addressLabel = current.usedSpk.address.address,
          message = current.draft,
          validationError = validationError,
          onMessageChanged = { state = current.copy(draft = it) },
          onContinue = {
            val message = ProveAddressMessage.create(current.draft).get()
              ?: return@EnterProveAddressMessageBodyModel
            state = ConfirmOnHardware(
              addresses = current.addresses,
              usedSpk = current.usedSpk,
              message = message
            )
          }
        ).asRootScreen()
      }

      is ConfirmOnHardware -> confirmOnHardwareScreen(
        current = current,
        setState = { state = it }
      )

      is Done -> {
        val export = current.proof.exportString()
        ProveAddressDoneBodyModel(
          addressLabel = current.proof.address.address,
          message = current.proof.message.value,
          proofExport = export,
          onShare = {
            sharingManager.shareText(
              text = export,
              title = "Address proof",
              completion = {}
            )
          },
          onCopy = {
            clipboard.setItem(PlainText(data = export))
          },
          onDone = props.onExit
        ).asRootScreen()
      }

      is ShowingError -> ErrorFormBodyModel(
        title = "Couldn't prove address",
        subline = "Something went wrong. Please try again.",
        primaryButton = ButtonDataModel(
          text = "Try again",
          onClick = { state = current.retry }
        ),
        secondaryButton = ButtonDataModel(text = "Cancel", onClick = props.onExit),
        onBack = props.onExit,
        eventTrackerScreenId = ProveAddressEventTrackerScreenId.PROVE_ADDRESS_ERROR,
        errorData = ErrorData(
          segment = SettingsAppSegment.ProveAddress,
          actionDescription = "Prove address",
          cause = current.cause
        )
      ).asRootScreen()
    }
  }

  @Composable
  private fun confirmOnHardwareScreen(
    current: ConfirmOnHardware,
    setState: (State) -> Unit,
  ): ScreenModel {
    val scope = rememberCoroutineScope()
    val change = remember(current.usedSpk.path.keychain) {
      current.usedSpk.path.keychain.toChange()
    }
    val enterMessageRetry = EnterMessage(
      addresses = current.addresses,
      usedSpk = current.usedSpk,
      draft = current.message.value
    )

    return nfcConfirmableSessionUiStateMachine.model(
      NfcConfirmableSessionUIStateMachineProps(
        session = { session, commands ->
          val script = sortedMultiScriptResolver
            .resolve(
              path = current.usedSpk.path,
              expectedScriptPubKey = current.usedSpk.scriptPubKey
            )
            .getOrThrow()
          val challenge = Bip322Challenge.create(
            usedSpk = current.usedSpk,
            message = current.message,
            script = script
          ).getOrThrow()
          commands.signBip322Sighash(
            session = session,
            digest = challenge.sighash.bytes,
            change = change,
            addressIndex = current.usedSpk.path.index,
            address = current.usedSpk.address.address,
            message = current.message.value
          )
        },
        onSuccess = { signatureBytes: ByteString ->
          val hwSignature = CompactEcdsaSignature.create(signatureBytes).get()
          if (hwSignature == null) {
            setState(
              ShowingError(
                cause = Error("Invalid HW compact signature"),
                retry = enterMessageRetry
              )
            )
          } else {
            val hwSigner = HwBip322SighashSigner { _, _, _, _ -> Ok(hwSignature) }
            proveAddressService
              .prove(
                usedSpk = current.usedSpk,
                message = current.message,
                hwSigner = hwSigner
              )
              .logFailure { "Prove address failed after HW signature" }
              .onSuccess { proof ->
                setState(Done(proof = proof))
              }
              .onFailure { error ->
                setState(ShowingError(cause = error, retry = enterMessageRetry))
              }
          }
        },
        onCancel = {
          setState(enterMessageRetry)
        },
        onError = { exception ->
          scope.launch {
            setState(ShowingError(cause = exception, retry = enterMessageRetry))
          }
          true
        },
        needsAuthentication = true,
        shouldLock = true,
        segment = SettingsAppSegment.ProveAddress,
        actionDescription = "Signing BIP-322 sighash on hardware",
        screenPresentationStyle = ScreenPresentationStyle.Root,
        eventTrackerContext = NfcEventTrackerScreenIdContext.BIP322_SIGHASH,
        confirmationContent = HardwareConfirmationContent.ProveAddress,
        confirmationResultContent = ConfirmationResultContent(
          pendingHeadline = "Review on Bitkey",
          pendingSubline = "Confirm the address and message on your Bitkey, then tap again.",
          deniedHeadline = "Address proof was not confirmed on your Bitkey"
        )
      )
    )
  }

  private fun messageValidationError(draft: String): String? {
    if (draft.isBlank()) return null
    return when (val error = ProveAddressMessage.create(draft).getError()) {
      null -> null
      is ProveAddressMessageError.Blank -> "Message can't be blank"
      is ProveAddressMessageError.TooLong ->
        "Message must be ${ProveAddressMessage.MAX_LENGTH} characters or fewer"
    }
  }

  private sealed interface State {
    data object LoadingUsedAddresses : State

    data object NoUsedAddresses : State

    data class SelectUsedAddress(val addresses: List<UsedScriptPubKey>) : State

    data class EnterMessage(
      val addresses: List<UsedScriptPubKey>,
      val usedSpk: UsedScriptPubKey,
      val draft: String,
    ) : State

    data class ConfirmOnHardware(
      val addresses: List<UsedScriptPubKey>,
      val usedSpk: UsedScriptPubKey,
      val message: ProveAddressMessage,
    ) : State

    data class Done(val proof: Bip322SimpleProof) : State

    data class ShowingError(
      val cause: Throwable,
      val retry: State,
    ) : State
  }
}

private fun BdkKeychainKind.toChange(): UInt =
  when (this) {
    BdkKeychainKind.EXTERNAL -> 0u
    BdkKeychainKind.INTERNAL -> 1u
  }
