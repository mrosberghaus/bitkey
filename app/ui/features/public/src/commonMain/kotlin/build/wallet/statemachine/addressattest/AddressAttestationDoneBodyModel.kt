package build.wallet.statemachine.addressattest

import build.wallet.analytics.events.screen.id.AddressAttestationEventTrackerScreenId
import build.wallet.compose.collections.immutableListOf
import build.wallet.statemachine.core.Icon
import build.wallet.statemachine.core.form.FormBodyModel
import build.wallet.statemachine.core.form.FormHeaderModel
import build.wallet.statemachine.core.form.FormMainContentModel.DataList
import build.wallet.ui.model.StandardClick
import build.wallet.ui.model.button.ButtonModel
import build.wallet.ui.model.button.ButtonModel.Size.Footer
import build.wallet.ui.model.button.ButtonModel.Treatment.Secondary

data class AddressAttestationDoneBodyModel(
  val addressLabel: String,
  val message: String,
  val encodedHex: String,
  val onShare: () -> Unit,
  val onCopy: () -> Unit,
  val onDone: () -> Unit,
) : FormBodyModel(
    id = AddressAttestationEventTrackerScreenId.ATTESTATION_DONE,
    onBack = onDone,
    toolbar = null,
    header = FormHeaderModel(
      icon = Icon.LargeIconCheckFilled,
      headline = "Address proved",
      subline = "Your attestation is ready to share."
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
            title = "Attestation (hex)",
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
