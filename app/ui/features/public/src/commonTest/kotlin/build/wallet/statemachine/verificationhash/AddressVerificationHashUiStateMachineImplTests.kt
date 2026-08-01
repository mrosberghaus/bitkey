package build.wallet.statemachine.verificationhash

import app.cash.turbine.plusAssign
import build.wallet.bdk.bindings.BdkKeychainKind
import build.wallet.bitcoin.BitcoinNetworkType
import build.wallet.bitcoin.address.BitcoinAddress
import build.wallet.bitcoin.verificationhash.AddressVerificationHashServiceFake
import build.wallet.bitcoin.verificationhash.SpendingChildPath
import build.wallet.bitcoin.verificationhash.UsedScriptPubKey
import build.wallet.bitcoin.transactions.BitcoinWalletServiceFake
import build.wallet.bitcoin.wallet.SpendingWalletMock
import build.wallet.bitkey.keybox.FullAccountMock
import build.wallet.coroutines.turbine.turbines
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
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotBeBlank
import io.kotest.matchers.types.shouldBeTypeOf
import okio.ByteString
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.toByteString

class AddressVerificationHashUiStateMachineImplTests : FunSpec({
  val usedSpk = UsedScriptPubKey(
    network = BitcoinNetworkType.SIGNET,
    address = BitcoinAddress("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"),
    scriptPubKey = "0014751e76e8199196d454941c45d1b3a323f1433bd6".decodeHex(),
    path = SpendingChildPath(BdkKeychainKind.EXTERNAL, 1u)
  )

  val spendingWallet = SpendingWalletMock(turbines::create)
  val bitcoinWalletService = BitcoinWalletServiceFake()
  val verificationHashService = AddressVerificationHashServiceFake()
  val nfcConfirmableSessionUiStateMachine =
    NfcConfirmableSessionUiStateMachineMock(id = "verification-hash-nfc")
  val sharingManager = SharingManagerFake()
  val clipboard = ClipboardMock()
  val hwSignatureBytes: ByteString = ByteArray(64) { 0x42 }.toByteString()

  val stateMachine = AddressVerificationHashUiStateMachineImpl(
    bitcoinWalletService = bitcoinWalletService,
    addressVerificationHashService = verificationHashService,
    nfcConfirmableSessionUiStateMachine = nfcConfirmableSessionUiStateMachine,
    sharingManager = sharingManager,
    clipboard = clipboard
  )

  val onExitCalls = turbines.create<Unit>("onExit")
  val props = AddressVerificationHashUiProps(
    account = FullAccountMock,
    onExit = { onExitCalls += Unit }
  )

  beforeTest {
    spendingWallet.reset()
    spendingWallet.listUsedScriptPubKeysResult = Ok(listOf(usedSpk))
    bitcoinWalletService.spendingWallet.value = spendingWallet
    verificationHashService.reset()
    clipboard.plainTextItemToReturn = null
  }

  test("happy path: select address, enter message, NFC sign, done with hex") {
    stateMachine.test(props) {
      awaitBody<LoadingSuccessBodyModel>()
      awaitBody<SelectUsedAddressBodyModel> {
        usedAddresses.shouldBe(listOf(usedSpk))
        onAddressSelected(usedSpk)
      }
      awaitBody<EnterVerificationMessageBodyModel> {
        onMessageChanged("prove ownership")
      }
      awaitBody<EnterVerificationMessageBodyModel> {
        message.shouldBe("prove ownership")
        clickPrimaryButton()
      }
      awaitBodyMock<NfcConfirmableSessionUIStateMachineProps<ByteString>>(
        id = "verification-hash-nfc"
      ) {
        onSuccess(hwSignatureBytes)
      }
      lateinit var expectedHex: String
      awaitBody<VerificationHashDoneBodyModel> {
        addressLabel.shouldBe(usedSpk.address.address)
        this.message.shouldBe("prove ownership")
        encodedHex.shouldNotBeBlank()
        expectedHex = encodedHex
        verificationHashService.createCount.shouldBe(1)
        verificationHashService.lastMessage?.value.shouldBe("prove ownership")
        onCopy()
      }
      clipboard.getPlainTextItem()
        .shouldBeTypeOf<PlainText>()
        .data
        .shouldBe(expectedHex)
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

  test("attest failure shows error and retry returns to message") {
    verificationHashService.result = Err(Error("sign failed"))
    stateMachine.test(props) {
      awaitBody<LoadingSuccessBodyModel>()
      awaitBody<SelectUsedAddressBodyModel> {
        onAddressSelected(usedSpk)
      }
      awaitBody<EnterVerificationMessageBodyModel> {
        onMessageChanged("retry me")
      }
      awaitBody<EnterVerificationMessageBodyModel> {
        clickPrimaryButton()
      }
      awaitBodyMock<NfcConfirmableSessionUIStateMachineProps<ByteString>>(
        id = "verification-hash-nfc"
      ) {
        onSuccess(hwSignatureBytes)
      }
      awaitBody<FormBodyModel> {
        header.shouldNotBeNull().headline.shouldBe("Couldn't prove address")
        primaryButton.shouldNotBeNull().onClick.invoke()
      }
      awaitBody<EnterVerificationMessageBodyModel> {
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
      awaitBody<EnterVerificationMessageBodyModel> {
        primaryButton.shouldNotBeNull().isEnabled.shouldBeFalse()
        onMessageChanged("   ")
      }
      awaitBody<EnterVerificationMessageBodyModel> {
        primaryButton.shouldNotBeNull().isEnabled.shouldBeFalse()
      }
    }
  }
})
