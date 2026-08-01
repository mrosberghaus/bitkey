package build.wallet.nfc

import okio.ByteString.Companion.toByteString

/** Stub signer for tests that do not exercise address attestation crypto. */
val FakeHwAttestationDigestSignerStub =
  FakeHwAttestationDigestSigner { _, _, _, _, _ ->
    ByteArray(64) { 0x42 }.toByteString()
  }
