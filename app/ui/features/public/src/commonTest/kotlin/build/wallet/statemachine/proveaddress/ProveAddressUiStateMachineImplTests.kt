package build.wallet.statemachine.proveaddress

import app.cash.turbine.plusAssign
import build.wallet.bdk.bindings.BdkKeychainKind
import build.wallet.bitcoin.BitcoinNetworkType
import build.wallet.bitcoin.address.BitcoinAddress
import build.wallet.bitcoin.bip322.ProveAddressServiceFake
import build.wallet.bitcoin.bip322.SortedMultiScript
import build.wallet.bitcoin.bip322.SortedMultiScriptResolver
import build.wallet.bitcoin.bip322.SpendingChildPath
import build.wallet.bitcoin.bip322.UsedScriptPubKey
import build.wallet.bitcoin.transactions.BitcoinWalletServiceFake
import build.wallet.bitcoin.wallet.SpendingWalletMock
import build.wallet.bitkey.keybox.FullAccountMock
import build.wallet.coroutines.turbine.turbines
import build.wallet.encrypt.Secp256k1PublicKey
import build.wallet.platform.clipboard.ClipItem.PlainText
import build.wallet.platform.clipboard.ClipboardMock
import build.wallet.platform.sharing.SharingManagerFake
import build.wallet.statemachine.core.LoadingSuccessBodyModel
import build.wallet.statemachine.core.form.FormBodyModel
import build.wallet.statemachine.core.test
import build.wallet.statemachine.nfc.NfcConfirmableSessionUIStateMachineProps
import build.wallet.statemachine.nfc.NfcConfirmableSessionUiStateMachineMock
import build.wallet.statemachine.ui.awaitBody
import build.wallet.statemachine.ui.awaitBodyMock
import build.wallet.statemachine.ui.clickPrimaryButton
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.getOrThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldStartWith
import io.kotest.matchers.types.shouldBeTypeOf
import okio.ByteString
import okio.ByteString.Companion.toByteString

class ProveAddressUiStateMachineImplTests : FunSpec({
  val app = Secp256k1PublicKey(
    "030c529e0ea40a00975d202624e39915daf7bdd2b71f31aa08596838781ce5f33a"
  )
  val hw = Secp256k1PublicKey(
    "027568b11f122ff8a7bc1c57e5c7642055bc618967b2f7bfe8e11fe99903c94dd3"
  )
  val server = Secp256k1PublicKey(
    "020a8bdf79cfa421d9655e9282800f115ff1d9db1e721ceb4248a3fcfec7faa67c"
  )
  val script = SortedMultiScript.fromChildPubkeys(app = app, hw = hw, server = server).getOrThrow()
  val scriptPubKey = SortedMultiScript.p2wshScriptPubKey(script.witnessScript)
  val usedSpk = UsedScriptPubKey(
    network = BitcoinNetworkType.SIGNET,
    address = BitcoinAddress("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"),
    scriptPubKey = scriptPubKey,
    path = SpendingChildPath(BdkKeychainKind.EXTERNAL, 1u)
  )

  val spendingWallet = SpendingWalletMock(turbines::create)
  val bitcoinWalletService = BitcoinWalletServiceFake()
  val proveAddressService = ProveAddressServiceFake()
  val scriptResolver = SortedMultiScriptResolver { _, _ -> Ok(script) }
  val nfcConfirmableSessionUiStateMachine =
    NfcConfirmableSessionUiStateMachineMock(id = "prove-address-nfc")
  val sharingManager = SharingManagerFake()
  val clipboard = ClipboardMock()
  val hwSignatureBytes: ByteString = ByteArray(64) { 0x42 }.toByteString()

  val stateMachine = ProveAddressUiStateMachineImpl(
    bitcoinWalletService = bitcoinWalletService,
    proveAddressService = proveAddressService,
    sortedMultiScriptResolver = scriptResolver,
    nfcConfirmableSessionUiStateMachine = nfcConfirmableSessionUiStateMachine,
    sharingManager = sharingManager,
    clipboard = clipboard
  )

  val onExitCalls = turbines.create<Unit>("onExit")
  val props = ProveAddressUiProps(
    account = FullAccountMock,
    onExit = { onExitCalls += Unit }
  )

  beforeTest {
    spendingWallet.reset()
    spendingWallet.listUsedScriptPubKeysResult = Ok(listOf(usedSpk))
    bitcoinWalletService.spendingWallet.value = spendingWallet
    proveAddressService.reset()
    clipboard.plainTextItemToReturn = null
  }

  test("happy path: select address, enter message, NFC sign, done with smp export") {
    stateMachine.test(props) {
      awaitBody<LoadingSuccessBodyModel>()
      awaitBody<SelectUsedAddressBodyModel> {
        usedAddresses.shouldBe(listOf(usedSpk))
        onAddressSelected(usedSpk)
      }
      awaitBody<EnterProveAddressMessageBodyModel> {
        onMessageChanged("prove ownership")
      }
      awaitBody<EnterProveAddressMessageBodyModel> {
        message.shouldBe("prove ownership")
        clickPrimaryButton()
      }
      awaitBodyMock<NfcConfirmableSessionUIStateMachineProps<ByteString>>(
        id = "prove-address-nfc"
      ) {
        onSuccess(hwSignatureBytes)
      }
      lateinit var expectedExport: String
      awaitBody<ProveAddressDoneBodyModel> {
        addressLabel.shouldBe(usedSpk.address.address)
        this.message.shouldBe("prove ownership")
        proofExport.shouldStartWith("smp")
        expectedExport = proofExport
        proveAddressService.proveCount.shouldBe(1)
        proveAddressService.lastMessage?.value.shouldBe("prove ownership")
        onCopy()
      }
      clipboard.getPlainTextItem()
        .shouldBeTypeOf<PlainText>()
        .data
        .shouldBe(expectedExport)
    }
  }

  test("empty used addresses shows empty state") {
    spendingWallet.listUsedScriptPubKeysResult = Ok(emptyList())
    stateMachine.test(props) {
      awaitBody<LoadingSuccessBodyModel>()
      awaitBody<FormBodyModel> {
        header.shouldNotBeNull().headline.shouldBe("No used addresses")
        primaryButton.shouldNotBeNull().onClick.invoke()
      }
      onExitCalls.awaitItem()
    }
  }

  test("list failure shows error") {
    spendingWallet.listUsedScriptPubKeysResult = Err(Error("list failed"))
    stateMachine.test(props) {
      awaitBody<LoadingSuccessBodyModel>()
      awaitBody<FormBodyModel> {
        header.shouldNotBeNull().headline.shouldBe("Couldn't prove address")
      }
    }
  }

  test("prove failure shows error and retry returns to message") {
    proveAddressService.result = Err(Error("sign failed"))
    stateMachine.test(props) {
      awaitBody<LoadingSuccessBodyModel>()
      awaitBody<SelectUsedAddressBodyModel> {
        onAddressSelected(usedSpk)
      }
      awaitBody<EnterProveAddressMessageBodyModel> {
        onMessageChanged("retry me")
      }
      awaitBody<EnterProveAddressMessageBodyModel> {
        clickPrimaryButton()
      }
      awaitBodyMock<NfcConfirmableSessionUIStateMachineProps<ByteString>>(
        id = "prove-address-nfc"
      ) {
        onSuccess(hwSignatureBytes)
      }
      awaitBody<FormBodyModel> {
        header.shouldNotBeNull().headline.shouldBe("Couldn't prove address")
        primaryButton.shouldNotBeNull().onClick.invoke()
      }
      awaitBody<EnterProveAddressMessageBodyModel> {
        message.shouldBe("retry me")
      }
    }
  }

  test("blank message keeps continue disabled") {
    stateMachine.test(props) {
      awaitBody<LoadingSuccessBodyModel>()
      awaitBody<SelectUsedAddressBodyModel> {
        onAddressSelected(usedSpk)
      }
      awaitBody<EnterProveAddressMessageBodyModel> {
        primaryButton.shouldNotBeNull().isEnabled.shouldBeFalse()
        onMessageChanged("   ")
      }
      awaitBody<EnterProveAddressMessageBodyModel> {
        primaryButton.shouldNotBeNull().isEnabled.shouldBeFalse()
      }
    }
  }
})
