package build.wallet.bitcoin.bip322

import build.wallet.bdk.bindings.BdkKeychainKind
import build.wallet.bitcoin.BitcoinNetworkType
import build.wallet.bitcoin.address.BitcoinAddress
import build.wallet.bitcoin.wallet.SpendingWalletFake
import build.wallet.bitcoin.wallet.WatchingWalletMock
import build.wallet.testing.shouldBeOk
import com.github.michaelbull.result.Ok
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.shouldBe
import okio.ByteString.Companion.decodeHex

class ListUsedScriptPubKeysTests : FunSpec({
  val spk1 = UsedScriptPubKey(
    network = BitcoinNetworkType.SIGNET,
    address = BitcoinAddress("tb1q1"),
    scriptPubKey = "001411".decodeHex(),
    path = SpendingChildPath(BdkKeychainKind.EXTERNAL, 0u)
  )
  val spk2 = UsedScriptPubKey(
    network = BitcoinNetworkType.SIGNET,
    address = BitcoinAddress("tb1q2"),
    scriptPubKey = "001422".decodeHex(),
    path = SpendingChildPath(BdkKeychainKind.INTERNAL, 1u)
  )

  test("WatchingWalletMock returns configured used script pubkeys") {
    val wallet = WatchingWalletMock(
      listUsedScriptPubKeysResult = Ok(listOf(spk1, spk2))
    )

    wallet.listUsedScriptPubKeys().shouldBeOk() shouldContainExactly listOf(spk1, spk2)
  }

  test("SpendingWalletFake returns configured used script pubkeys") {
    val wallet = SpendingWalletFake(networkType = BitcoinNetworkType.SIGNET)
    wallet.usedScriptPubKeys = listOf(spk1)

    wallet.listUsedScriptPubKeys().shouldBeOk() shouldBe listOf(spk1)
  }
})
