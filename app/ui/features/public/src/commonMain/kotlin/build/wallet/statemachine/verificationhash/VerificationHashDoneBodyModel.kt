package build.wallet.statemachine.verificationhash

import build.wallet.analytics.events.screen.id.VerificationHashEventTrackerScreenId
import build.wallet.compose.collections.immutableListOf
import build.wallet.statemachine.core.Icon
import build.wallet.statemachine.core.form.FormBodyModel
import build.wallet.statemachine.core.form.FormHeaderModel
import build.wallet.statemachine.core.form.FormMainContentModel.DataList
import build.wallet.ui.model.StandardClick
import build.wallet.ui.model.button.ButtonModel
import build.wallet.ui.model.button.ButtonModel.Size.Footer
import build.wallet.ui.model.button.ButtonModel.Treatment.Secondary

data class VerificationHashDoneBodyModel(
  val addressLabel: String,
  val message: String,
  val encodedHex: String,
  val onShare: () -> Unit,
  val onCopy: () -> Unit,
  val onDone: () -> Unit,
) : FormBodyModel(
    id = VerificationHashEventTrackerScreenId.VERIFICATION_HASH_DONE,
    onBack = onDone,
    toolbar = null,
    header = FormHeaderModel(
      icon = Icon.LargeIconCheckFilled,
      headline = "Address proved",
      subline = "Your verification hash is ready to share."
    ),
    mainContentList = immutableListOf(
      DataList(
        items = immutableListOf(
          DataList.Data(
            title = "Address",
            sideText = addressLabel
          ),
          DataList.Data(
            title = "Message",
            sideText = message
          ),
          DataList.Data(
            title = "Verification hash",
            sideText = encodedHex.take(24) + if (encodedHex.length > 24) "…" else ""
          )
        )
      )
    ),
    primaryButton = ButtonModel(
      text = "Share",
      onClick = StandardClick(onShare),
      size = Footer
    ),
    secondaryButton = ButtonModel(
      text = "Copy",
      onClick = StandardClick(onCopy),
      treatment = Secondary,
      size = Footer
    ),
    tertiaryButton = ButtonModel(
      text = "Done",
      onClick = StandardClick(onDone),
      treatment = Secondary,
      size = Footer
    )
  )
