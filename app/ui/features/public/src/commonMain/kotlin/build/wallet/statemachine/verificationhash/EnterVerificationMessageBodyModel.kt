package build.wallet.statemachine.verificationhash

import build.wallet.analytics.events.screen.id.VerificationHashEventTrackerScreenId
import build.wallet.bitcoin.verificationhash.VerificationMessage
import build.wallet.compose.collections.immutableListOf
import build.wallet.statemachine.core.form.FormBodyModel
import build.wallet.statemachine.core.form.FormHeaderModel
import build.wallet.statemachine.core.form.FormMainContentModel.TextInput
import build.wallet.ui.model.StandardClick
import build.wallet.ui.model.button.ButtonModel
import build.wallet.ui.model.button.ButtonModel.Size.Footer
import build.wallet.ui.model.input.TextFieldModel
import build.wallet.ui.model.input.TextFieldModel.KeyboardType.Default
import build.wallet.ui.model.toolbar.ToolbarAccessoryModel.IconAccessory.Companion.BackAccessory
import build.wallet.ui.model.toolbar.ToolbarMiddleAccessoryModel
import build.wallet.ui.model.toolbar.ToolbarModel

data class EnterVerificationMessageBodyModel(
  override val onBack: () -> Unit,
  val addressLabel: String,
  val message: String,
  val validationError: String?,
  val onMessageChanged: (String) -> Unit,
  val onContinue: () -> Unit,
) : FormBodyModel(
    id = VerificationHashEventTrackerScreenId.ENTER_MESSAGE,
    onBack = onBack,
    toolbar = ToolbarModel(
      leadingAccessory = BackAccessory(onClick = onBack),
      middleAccessory = ToolbarMiddleAccessoryModel(title = "Prove address")
    ),
    header = FormHeaderModel(
      headline = "Enter a message",
      subline = validationError
        ?: "This message is signed with your app and hardware keys for $addressLabel."
    ),
    mainContentList = immutableListOf(
      TextInput(
        title = "Message",
        fieldModel = TextFieldModel(
          value = message,
          placeholderText = "I own this address",
          testTag = "verification-hash-message-input",
          onValueChange = { newValue, _ -> onMessageChanged(newValue) },
          keyboardType = Default,
          focusByDefault = true,
          maxLength = VerificationMessage.MAX_LENGTH
        )
      )
    ),
    primaryButton = ButtonModel(
      text = "Continue",
      isEnabled = validationError == null && message.isNotBlank(),
      onClick = StandardClick(onContinue),
      size = Footer
    )
  )
