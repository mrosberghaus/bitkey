package build.wallet.nfc

import okio.ByteString.Companion.toByteString

/** Stub signer for tests that do not exercise BIP-322 sighash crypto. */
val FakeHwBip322SighashSignerStub =
  FakeHwBip322SighashSigner { _, _, _, _, _ ->
    ByteArray(64) { 0x42 }.toByteString()
  }
