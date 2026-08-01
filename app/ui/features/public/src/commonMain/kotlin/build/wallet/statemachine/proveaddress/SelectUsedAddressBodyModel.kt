package build.wallet.statemachine.proveaddress

import build.wallet.analytics.events.screen.id.ProveAddressEventTrackerScreenId
import build.wallet.bitcoin.bip322.UsedScriptPubKey
import build.wallet.compose.collections.immutableListOf
import build.wallet.statemachine.core.Icon
import build.wallet.statemachine.core.form.FormBodyModel
import build.wallet.statemachine.core.form.FormHeaderModel
import build.wallet.statemachine.core.form.FormMainContentModel.ListGroup
import build.wallet.ui.model.icon.IconBackgroundType.Transient
import build.wallet.ui.model.icon.IconModel
import build.wallet.ui.model.icon.IconSize.Small
import build.wallet.ui.model.list.ListGroupModel
import build.wallet.ui.model.list.ListGroupStyle.DIVIDER
import build.wallet.ui.model.list.ListItemAccessory.IconAccessory
import build.wallet.ui.model.list.ListItemModel
import build.wallet.ui.model.toolbar.ToolbarAccessoryModel.IconAccessory.Companion.BackAccessory
import build.wallet.ui.model.toolbar.ToolbarMiddleAccessoryModel
import build.wallet.ui.model.toolbar.ToolbarModel
import kotlinx.collections.immutable.toImmutableList

data class SelectUsedAddressBodyModel(
  override val onBack: () -> Unit,
  val usedAddresses: List<UsedScriptPubKey>,
  val onAddressSelected: (UsedScriptPubKey) -> Unit,
) : FormBodyModel(
    id = ProveAddressEventTrackerScreenId.SELECT_USED_ADDRESS,
    onBack = onBack,
    toolbar = ToolbarModel(
      leadingAccessory = BackAccessory(onClick = onBack),
      middleAccessory = ToolbarMiddleAccessoryModel(title = "Prove address")
    ),
    header = FormHeaderModel(
      headline = "Choose an address",
      subline = "Select a used receive or change address to prove."
    ),
    mainContentList = immutableListOf(
      ListGroup(
        listGroupModel = ListGroupModel(
          items = usedAddresses.map { usedSpk ->
            ListItemModel(
              title = usedSpk.address.address,
              secondaryText = pathLabel(usedSpk),
              trailingAccessory = IconAccessory(
                model = IconModel(
                  icon = Icon.CaretRight,
                  iconSize = Small,
                  iconBackgroundType = Transient
                ),
                onClick = { onAddressSelected(usedSpk) }
              ),
              onClick = { onAddressSelected(usedSpk) }
            )
          }.toImmutableList(),
          style = DIVIDER
        )
      )
    ),
    primaryButton = null
  )

private fun pathLabel(usedSpk: UsedScriptPubKey): String =
  "${usedSpk.path.keychain} / ${usedSpk.path.index}"
