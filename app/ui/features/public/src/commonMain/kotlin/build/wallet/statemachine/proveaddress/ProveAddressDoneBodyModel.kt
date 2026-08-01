package build.wallet.statemachine.proveaddress

import build.wallet.analytics.events.screen.id.ProveAddressEventTrackerScreenId
import build.wallet.compose.collections.immutableListOf
import build.wallet.statemachine.core.Icon
import build.wallet.statemachine.core.form.FormBodyModel
import build.wallet.statemachine.core.form.FormHeaderModel
import build.wallet.statemachine.core.form.FormMainContentModel.DataList
import build.wallet.ui.model.StandardClick
import build.wallet.ui.model.button.ButtonModel
import build.wallet.ui.model.button.ButtonModel.Size.Footer
import build.wallet.ui.model.button.ButtonModel.Treatment.Secondary

data class ProveAddressDoneBodyModel(
  val addressLabel: String,
  val message: String,
  val proofExport: String,
  val onShare: () -> Unit,
  val onCopy: () -> Unit,
  val onDone: () -> Unit,
) : FormBodyModel(
    id = ProveAddressEventTrackerScreenId.PROVE_ADDRESS_DONE,
    onBack = onDone,
    toolbar = null,
    header = FormHeaderModel(
      icon = Icon.LargeIconCheckFilled,
      headline = "Address proved",
      subline = "Your BIP-322 signature is ready to share."
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
            title = "BIP-322 signature",
            sideText = proofExport.take(24) + if (proofExport.length > 24) "…" else ""
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
