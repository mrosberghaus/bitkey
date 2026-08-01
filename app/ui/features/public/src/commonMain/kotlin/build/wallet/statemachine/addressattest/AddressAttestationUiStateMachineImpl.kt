package build.wallet.statemachine.addressattest

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import build.wallet.analytics.events.screen.context.NfcEventTrackerScreenIdContext
import build.wallet.analytics.events.screen.id.AddressAttestationEventTrackerScreenId
import build.wallet.bdk.bindings.BdkKeychainKind
import build.wallet.bitcoin.attestation.AddressAttestation
import build.wallet.bitcoin.attestation.AddressAttestationChallenge
import build.wallet.bitcoin.attestation.AddressAttestationService
import build.wallet.bitcoin.attestation.AttestationMessage
import build.wallet.bitcoin.attestation.AttestationMessageError
import build.wallet.bitcoin.attestation.CompactEcdsaSignature
import build.wallet.bitcoin.attestation.HwAttestationSigner
import build.wallet.bitcoin.attestation.UsedScriptPubKey
import build.wallet.bitcoin.transactions.BitcoinWalletService
import build.wallet.di.ActivityScope
import build.wallet.di.BitkeyInject
import build.wallet.logging.logFailure
import build.wallet.platform.clipboard.ClipItem.PlainText
import build.wallet.platform.clipboard.Clipboard
import build.wallet.platform.sharing.SharingManager
import build.wallet.statemachine.addressattest.AddressAttestationUiStateMachineImpl.State.ConfirmOnHardware
import build.wallet.statemachine.addressattest.AddressAttestationUiStateMachineImpl.State.Done
import build.wallet.statemachine.addressattest.AddressAttestationUiStateMachineImpl.State.EnterMessage
import build.wallet.statemachine.addressattest.AddressAttestationUiStateMachineImpl.State.LoadingUsedAddresses
import build.wallet.statemachine.addressattest.AddressAttestationUiStateMachineImpl.State.NoUsedAddresses
import build.wallet.statemachine.addressattest.AddressAttestationUiStateMachineImpl.State.SelectUsedAddress
import build.wallet.statemachine.addressattest.AddressAttestationUiStateMachineImpl.State.ShowingError
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
import build.wallet.statemachine.send.hardwareconfirmation.HardwareConfirmationContent
import build.wallet.statemachine.settings.SettingsAppSegment
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.get
import com.github.michaelbull.result.getError
import com.github.michaelbull.result.onFailure
import com.github.michaelbull.result.onSuccess
import kotlinx.coroutines.launch
import okio.ByteString

@BitkeyInject(ActivityScope::class)
class AddressAttestationUiStateMachineImpl(
  private val bitcoinWalletService: BitcoinWalletService,
  private val addressAttestationService: AddressAttestationService,
  private val nfcConfirmableSessionUiStateMachine: NfcConfirmableSessionUiStateMachine,
  private val sharingManager: SharingManager,
  private val clipboard: Clipboard,
) : AddressAttestationUiStateMachine {
  @Composable
  override fun model(props: AddressAttestationUiProps): ScreenModel {
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
            .logFailure { "Failed to list used scriptPubKeys for attestation" }
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
          id = AddressAttestationEventTrackerScreenId.LOADING_USED_ADDRESSES
        ).asRootScreen()
      }

      is NoUsedAddresses -> ErrorFormBodyModel(
        title = "No used addresses",
        subline = "Receive or send bitcoin first, then try again.",
        primaryButton = ButtonDataModel(text = "OK", onClick = props.onExit),
        onBack = props.onExit,
        eventTrackerScreenId = AddressAttestationEventTrackerScreenId.NO_USED_ADDRESSES,
        errorData = ErrorData(
          segment = SettingsAppSegment.AddressAttestation,
          actionDescription = "Listing used addresses for attestation",
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
        EnterAttestationMessageBodyModel(
          onBack = {
            state = SelectUsedAddress(current.addresses)
          },
          addressLabel = current.usedSpk.address.address,
          message = current.draft,
          validationError = validationError,
          onMessageChanged = { state = current.copy(draft = it) },
          onContinue = {
            val message = AttestationMessage.create(current.draft).get()
              ?: return@EnterAttestationMessageBodyModel
            state = ConfirmOnHardware(
              addresses = current.addresses,
              usedSpk = current.usedSpk,
              message = message
            )
          }
        ).asRootScreen()
      }

      is ConfirmOnHardware -> confirmOnHardwareScreen(
        props = props,
        current = current,
        setState = { state = it }
      )

      is Done -> {
        val encodedHex = current.attestation.encode().hex()
        AddressAttestationDoneBodyModel(
          addressLabel = current.attestation.address.address,
          message = current.attestation.message.value,
          encodedHex = encodedHex,
          onShare = {
            sharingManager.shareText(
              text = encodedHex,
              title = "Address attestation",
              completion = {}
            )
          },
          onCopy = {
            clipboard.setItem(PlainText(data = encodedHex))
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
        eventTrackerScreenId = AddressAttestationEventTrackerScreenId.ATTESTATION_ERROR,
        errorData = ErrorData(
          segment = SettingsAppSegment.AddressAttestation,
          actionDescription = "Address attestation",
          cause = current.cause
        )
      ).asRootScreen()
    }
  }

  @Composable
  private fun confirmOnHardwareScreen(
    props: AddressAttestationUiProps,
    current: ConfirmOnHardware,
    setState: (State) -> Unit,
  ): ScreenModel {
    val scope = rememberCoroutineScope()
    val challenge = remember(current.usedSpk, current.message) {
      AddressAttestationChallenge.create(
        network = current.usedSpk.network,
        address = current.usedSpk.address,
        scriptPubKey = current.usedSpk.scriptPubKey,
        path = current.usedSpk.path,
        message = current.message
      )
    }
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
          commands.signAddressAttestation(
            session = session,
            digest = challenge.digest,
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
            val hwSigner = HwAttestationSigner { _, _, _, _ -> Ok(hwSignature) }
            addressAttestationService
              .attest(
                usedSpk = current.usedSpk,
                message = current.message,
                hwSigner = hwSigner
              )
              .logFailure { "Address attestation failed after HW signature" }
              .onSuccess { attestation ->
                setState(Done(attestation = attestation))
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
        segment = SettingsAppSegment.AddressAttestation,
        actionDescription = "Signing address attestation on hardware",
        screenPresentationStyle = ScreenPresentationStyle.Root,
        eventTrackerContext = NfcEventTrackerScreenIdContext.ADDRESS_ATTESTATION,
        confirmationContent = HardwareConfirmationContent.AddressAttestation,
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
    return when (val error = AttestationMessage.create(draft).getError()) {
      null -> null
      is AttestationMessageError.Blank -> "Message can't be blank"
      is AttestationMessageError.TooLong ->
        "Message must be ${AttestationMessage.MAX_LENGTH} characters or fewer"
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
      val message: AttestationMessage,
    ) : State

    data class Done(val attestation: AddressAttestation) : State

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
