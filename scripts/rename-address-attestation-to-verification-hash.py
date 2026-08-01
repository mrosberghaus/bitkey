#!/usr/bin/env python3
"""Rename address attestation → verification hash (one-shot lever).

Rerun-safe for content replacements. Prefer git mv for paths.
Does NOT touch HW/spending-key attestation, SE attestation, or image signing.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Paths that must never be content-touched (unrelated attestation).
EXCLUDE_PATH_SUBSTRINGS = (
    "/server/",
    "wca/src/attestation.rs",
    "wca/src/commands/attestation.rs",
    "se_attestation",
    "firmware/python/bitkey/attestation.py",
    "firmware/hal/secure-engine/",
    "/_build/",
    "/target/",
    "/.git/",
    "node_modules/",
    "rename-address-attestation-to-verification-hash.py",
)

# Markers that identify address-attestation surface (any match → eligible).
ADDRESS_MARKERS = (
    "AddressAttestation",
    "addressattest",
    "BKAddressAttestation",
    "signAddressAttestation",
    "SignAddressAttestation",
    "sign_address_attestation",
    "address_attestation",
    "HwAttestationSigner",
    "FakeHwAttestationDigestSigner",
    "AttestationEcdsaCrypto",
    "AttestationMessage",
    "WatchingAttestation",
    "ADDRESS_ATTESTATION",
    "mobile-address-attestation",
    "confirm_address_attestation",
    "Address attestation",
    "Address Attestation",
    "address attestation",
    "bitcoin/attestation",
    "bitcoin.attestation",
    "ATTESTATION_DONE",
    "ATTESTATION_ERROR",
    "IPC_PROTO_SIGN_ADDRESS_ATTESTATION",
)

# Longest-first identifier / phrase replacements.
REPLACEMENTS: list[tuple[str, str]] = [
    # Packages / paths in imports and strings
    ("build.wallet.bitcoin.attestation", "build.wallet.bitcoin.verificationhash"),
    ("build.wallet.statemachine.addressattest", "build.wallet.statemachine.verificationhash"),
    ("bitcoin/attestation", "bitcoin/verificationhash"),
    ("statemachine/addressattest", "statemachine/verificationhash"),
    # Challenge before parent type
    ("AddressAttestationChallenge", "AddressVerificationChallenge"),
    ("AddressAttestationServiceImpl", "AddressVerificationHashServiceImpl"),
    ("AddressAttestationServiceFake", "AddressVerificationHashServiceFake"),
    ("AddressAttestationService", "AddressVerificationHashService"),
    ("AddressAttestationVerification", "AddressVerificationHashResult"),
    ("AddressAttestationInvalidReason", "AddressVerificationHashInvalidReason"),
    ("AddressAttestationDecodeError", "AddressVerificationHashDecodeError"),
    ("AddressAttestationEventTrackerScreenId", "VerificationHashEventTrackerScreenId"),
    ("AddressAttestationFeatureFlag", "VerificationHashFeatureFlag"),
    ("AddressAttestationUiStateMachineImpl", "AddressVerificationHashUiStateMachineImpl"),
    ("AddressAttestationUiStateMachine", "AddressVerificationHashUiStateMachine"),
    ("AddressAttestationUiProps", "AddressVerificationHashUiProps"),
    ("AddressAttestationDoneBodyModel", "VerificationHashDoneBodyModel"),
    ("EnterAttestationMessageBodyModel", "EnterVerificationMessageBodyModel"),
    ("ShowingAddressAttestationUiState", "ShowingVerificationHashUiState"),
    ("FakeHwAttestationDigestSignerUnsupported", "FakeHwVerificationHashDigestSignerUnsupported"),
    ("FakeHwAttestationDigestSignerImpl", "FakeHwVerificationHashDigestSignerImpl"),
    ("FakeHwAttestationDigestSignerStub", "FakeHwVerificationHashDigestSignerStub"),
    ("FakeHwAttestationDigestSigner", "FakeHwVerificationHashDigestSigner"),
    ("HwAttestationSignerFake", "HwVerificationHashSignerFake"),
    ("HwAttestationSigner", "HwVerificationHashSigner"),
    ("WatchingAttestationKeychain", "WatchingVerificationKeychain"),
    ("AttestationEcdsaCryptoUnsupported", "VerificationHashEcdsaCryptoUnsupported"),
    ("AttestationEcdsaCryptoImpl", "VerificationHashEcdsaCryptoImpl"),
    ("AttestationEcdsaCrypto", "VerificationHashEcdsaCrypto"),
    ("AttestationMessageError", "VerificationMessageError"),
    ("AttestationMessage", "VerificationMessage"),
    ("SignAddressAttestationResultState", "SignAddressVerificationHashResultState"),
    ("SignAddressAttestationResult", "SignAddressVerificationHashResult"),
    ("SignAddressAttestationCmd", "SignAddressVerificationHashCmd"),
    ("SignAddressAttestation", "SignAddressVerificationHash"),
    ("signAddressAttestation", "signAddressVerificationHash"),
    ("sign_address_attestation_cmd", "sign_address_verification_hash_cmd"),
    ("sign_address_attestation_rsp", "sign_address_verification_hash_rsp"),
    ("sign_address_attestation_result", "sign_address_verification_hash_result"),
    ("sign_address_attestation", "sign_address_verification_hash"),
    (
        "display_params_privileged_action_confirm_address_attestation",
        "display_params_privileged_action_confirm_address_verification_hash",
    ),
    ("confirm_address_attestation", "confirm_address_verification_hash"),
    ("address_attestation_clear_session", "address_verification_hash_clear_session"),
    ("address_attestation_handle_init", "address_verification_hash_handle_init"),
    ("address_attestation_register_handlers", "address_verification_hash_register_handlers"),
    ("address_attestation_session_t", "address_verification_hash_session_t"),
    ("address_attestation_impl.h", "address_verification_hash_impl.h"),
    ("address_attestation.c", "address_verification_hash.c"),
    ("address_attestation", "address_verification_hash"),
    ("IPC_PROTO_SIGN_ADDRESS_ATTESTATION_CMD", "IPC_PROTO_SIGN_ADDRESS_VERIFICATION_HASH_CMD"),
    ("BKAddressAttestation/v1", "BKAddressVerificationHash/v1"),
    ("mobile-address-attestation-enabled", "mobile-verification-hash-enabled"),
    ("ADDRESS_ATTESTATION", "ADDRESS_VERIFICATION_HASH"),
    ("ATTESTATION_DONE", "VERIFICATION_HASH_DONE"),
    ("ATTESTATION_ERROR", "VERIFICATION_HASH_ERROR"),
    ("addressAttestationFeatureFlag", "verificationHashFeatureFlag"),
    ("addressAttestationUiStateMachine", "addressVerificationHashUiStateMachine"),
    ("addressAttestationService", "addressVerificationHashService"),
    ("AddressAttestation", "AddressVerificationHash"),
    # User-facing copy (after type renames so class names already moved)
    ("Address Attestation", "Verification hash"),
    ("Address attestation", "Verification hash"),
    ("address attestation", "verification hash"),
    ("Your attestation is ready to share.", "Your verification hash is ready to share."),
    ("Attestation (hex)", "Verification hash"),
    ("with Bitkey attestation", "with a Bitkey verification hash"),
    # Method rename: service.attest → service.create
    ("override suspend fun attest(", "override suspend fun create("),
    ("suspend fun attest(", "suspend fun create("),
    (".attest(", ".create("),
    # Local / param names common in this feature
    ("attestationService", "verificationHashService"),
    ("val attestation =", "val verificationHash ="),
    ("val attestation:", "val verificationHash:"),
    ("(val attestation:", "(val verificationHash:"),
    ("attestation.digest", "verificationHash.digest"),
    ("attestation.path", "verificationHash.path"),
    ("attestation.address", "verificationHash.address"),
    ("attestation.scriptPubKey", "verificationHash.scriptPubKey"),
    ("attestation.message", "verificationHash.message"),
    ("attestation.appSignature", "verificationHash.appSignature"),
    ("attestation.hwSignature", "verificationHash.hwSignature"),
    ("attestation.network", "verificationHash.network"),
    ("attestation.encode", "verificationHash.encode"),
    ("(attestation,", "(verificationHash,"),
    ("(attestation)", "(verificationHash)"),
    (" attestation,", " verificationHash,"),
    (" attestation)", " verificationHash)"),
    (" attestation.", " verificationHash."),
    ("= attestation", "= verificationHash"),
    ("lastAttestation", "lastVerificationHash"),
]


DIR_MOVES: list[tuple[str, str]] = [
    (
        "app/domain/wallet/public/src/commonMain/kotlin/build/wallet/bitcoin/attestation",
        "app/domain/wallet/public/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash",
    ),
    (
        "app/domain/wallet/impl/src/commonMain/kotlin/build/wallet/bitcoin/attestation",
        "app/domain/wallet/impl/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash",
    ),
    (
        "app/domain/wallet/impl/src/commonJvmMain/kotlin/build/wallet/bitcoin/attestation",
        "app/domain/wallet/impl/src/commonJvmMain/kotlin/build/wallet/bitcoin/verificationhash",
    ),
    (
        "app/domain/wallet/impl/src/commonTest/kotlin/build/wallet/bitcoin/attestation",
        "app/domain/wallet/impl/src/commonTest/kotlin/build/wallet/bitcoin/verificationhash",
    ),
    (
        "app/domain/wallet/impl/src/jvmTest/kotlin/build/wallet/bitcoin/attestation",
        "app/domain/wallet/impl/src/jvmTest/kotlin/build/wallet/bitcoin/verificationhash",
    ),
    (
        "app/domain/wallet/impl/src/iosMain/kotlin/build/wallet/bitcoin/attestation",
        "app/domain/wallet/impl/src/iosMain/kotlin/build/wallet/bitcoin/verificationhash",
    ),
    (
        "app/domain/wallet/fake/src/commonMain/kotlin/build/wallet/bitcoin/attestation",
        "app/domain/wallet/fake/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash",
    ),
    (
        "app/ui/features/public/src/commonMain/kotlin/build/wallet/statemachine/addressattest",
        "app/ui/features/public/src/commonMain/kotlin/build/wallet/statemachine/verificationhash",
    ),
    (
        "app/ui/features/public/src/commonTest/kotlin/build/wallet/statemachine/addressattest",
        "app/ui/features/public/src/commonTest/kotlin/build/wallet/statemachine/verificationhash",
    ),
]

FILE_MOVES: list[tuple[str, str]] = [
    # Domain public
    (
        "app/domain/wallet/public/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash/AddressAttestation.kt",
        "app/domain/wallet/public/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash/AddressVerificationHash.kt",
    ),
    (
        "app/domain/wallet/public/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash/AddressAttestationChallenge.kt",
        "app/domain/wallet/public/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash/AddressVerificationChallenge.kt",
    ),
    (
        "app/domain/wallet/public/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash/AddressAttestationService.kt",
        "app/domain/wallet/public/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash/AddressVerificationHashService.kt",
    ),
    (
        "app/domain/wallet/public/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash/AddressAttestationVerification.kt",
        "app/domain/wallet/public/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash/AddressVerificationHashResult.kt",
    ),
    (
        "app/domain/wallet/public/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash/AttestationEcdsaCrypto.kt",
        "app/domain/wallet/public/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash/VerificationHashEcdsaCrypto.kt",
    ),
    (
        "app/domain/wallet/public/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash/AttestationMessage.kt",
        "app/domain/wallet/public/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash/VerificationMessage.kt",
    ),
    (
        "app/domain/wallet/public/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash/HwAttestationSigner.kt",
        "app/domain/wallet/public/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash/HwVerificationHashSigner.kt",
    ),
    (
        "app/domain/wallet/public/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash/WatchingAttestationKeychain.kt",
        "app/domain/wallet/public/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash/WatchingVerificationKeychain.kt",
    ),
    # Domain impl / fake / tests
    (
        "app/domain/wallet/impl/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash/AddressAttestationServiceImpl.kt",
        "app/domain/wallet/impl/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash/AddressVerificationHashServiceImpl.kt",
    ),
    (
        "app/domain/wallet/impl/src/commonJvmMain/kotlin/build/wallet/bitcoin/verificationhash/AttestationEcdsaCryptoImpl.kt",
        "app/domain/wallet/impl/src/commonJvmMain/kotlin/build/wallet/bitcoin/verificationhash/VerificationHashEcdsaCryptoImpl.kt",
    ),
    (
        "app/domain/wallet/impl/src/iosMain/kotlin/build/wallet/bitcoin/verificationhash/AttestationEcdsaCryptoUnsupported.kt",
        "app/domain/wallet/impl/src/iosMain/kotlin/build/wallet/bitcoin/verificationhash/VerificationHashEcdsaCryptoUnsupported.kt",
    ),
    (
        "app/domain/wallet/fake/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash/AddressAttestationServiceFake.kt",
        "app/domain/wallet/fake/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash/AddressVerificationHashServiceFake.kt",
    ),
    (
        "app/domain/wallet/fake/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash/HwAttestationSignerFake.kt",
        "app/domain/wallet/fake/src/commonMain/kotlin/build/wallet/bitcoin/verificationhash/HwVerificationHashSignerFake.kt",
    ),
    (
        "app/domain/wallet/impl/src/commonTest/kotlin/build/wallet/bitcoin/verificationhash/AddressAttestationChallengeTests.kt",
        "app/domain/wallet/impl/src/commonTest/kotlin/build/wallet/bitcoin/verificationhash/AddressVerificationChallengeTests.kt",
    ),
    (
        "app/domain/wallet/impl/src/commonTest/kotlin/build/wallet/bitcoin/verificationhash/AddressAttestationServiceImplTests.kt",
        "app/domain/wallet/impl/src/commonTest/kotlin/build/wallet/bitcoin/verificationhash/AddressVerificationHashServiceImplTests.kt",
    ),
    (
        "app/domain/wallet/impl/src/commonTest/kotlin/build/wallet/bitcoin/verificationhash/AddressAttestationVerifyTests.kt",
        "app/domain/wallet/impl/src/commonTest/kotlin/build/wallet/bitcoin/verificationhash/AddressVerificationHashVerifyTests.kt",
    ),
    (
        "app/domain/wallet/impl/src/jvmTest/kotlin/build/wallet/bitcoin/verificationhash/AttestationEcdsaCryptoImplTests.kt",
        "app/domain/wallet/impl/src/jvmTest/kotlin/build/wallet/bitcoin/verificationhash/VerificationHashEcdsaCryptoImplTests.kt",
    ),
    # Feature flag / analytics
    (
        "app/domain/feature-flag/public/src/commonMain/kotlin/build/wallet/feature/flags/AddressAttestationFeatureFlag.kt",
        "app/domain/feature-flag/public/src/commonMain/kotlin/build/wallet/feature/flags/VerificationHashFeatureFlag.kt",
    ),
    (
        "app/domain/analytics/public/src/commonMain/kotlin/build/wallet/analytics/events/screen/id/AddressAttestationEventTrackerScreenId.kt",
        "app/domain/analytics/public/src/commonMain/kotlin/build/wallet/analytics/events/screen/id/VerificationHashEventTrackerScreenId.kt",
    ),
    # Hardware fake digest signers
    (
        "app/domain/hardware/impl/src/commonMain/kotlin/build/wallet/nfc/FakeHwAttestationDigestSigner.kt",
        "app/domain/hardware/impl/src/commonMain/kotlin/build/wallet/nfc/FakeHwVerificationHashDigestSigner.kt",
    ),
    (
        "app/domain/hardware/impl/src/commonJvmMain/kotlin/build/wallet/nfc/FakeHwAttestationDigestSignerImpl.kt",
        "app/domain/hardware/impl/src/commonJvmMain/kotlin/build/wallet/nfc/FakeHwVerificationHashDigestSignerImpl.kt",
    ),
    (
        "app/domain/hardware/impl/src/iosMain/kotlin/build/wallet/nfc/FakeHwAttestationDigestSignerUnsupported.kt",
        "app/domain/hardware/impl/src/iosMain/kotlin/build/wallet/nfc/FakeHwVerificationHashDigestSignerUnsupported.kt",
    ),
    (
        "app/domain/hardware/impl/src/commonTest/kotlin/build/wallet/nfc/FakeHwAttestationDigestSignerStub.kt",
        "app/domain/hardware/impl/src/commonTest/kotlin/build/wallet/nfc/FakeHwVerificationHashDigestSignerStub.kt",
    ),
    (
        "app/domain/hardware/impl/src/jvmTest/kotlin/build/wallet/nfc/FakeHwAttestationDigestSignerImplTests.kt",
        "app/domain/hardware/impl/src/jvmTest/kotlin/build/wallet/nfc/FakeHwVerificationHashDigestSignerImplTests.kt",
    ),
    # UI
    (
        "app/ui/features/public/src/commonMain/kotlin/build/wallet/statemachine/verificationhash/AddressAttestationUiStateMachine.kt",
        "app/ui/features/public/src/commonMain/kotlin/build/wallet/statemachine/verificationhash/AddressVerificationHashUiStateMachine.kt",
    ),
    (
        "app/ui/features/public/src/commonMain/kotlin/build/wallet/statemachine/verificationhash/AddressAttestationUiStateMachineImpl.kt",
        "app/ui/features/public/src/commonMain/kotlin/build/wallet/statemachine/verificationhash/AddressVerificationHashUiStateMachineImpl.kt",
    ),
    (
        "app/ui/features/public/src/commonMain/kotlin/build/wallet/statemachine/verificationhash/AddressAttestationDoneBodyModel.kt",
        "app/ui/features/public/src/commonMain/kotlin/build/wallet/statemachine/verificationhash/VerificationHashDoneBodyModel.kt",
    ),
    (
        "app/ui/features/public/src/commonMain/kotlin/build/wallet/statemachine/verificationhash/EnterAttestationMessageBodyModel.kt",
        "app/ui/features/public/src/commonMain/kotlin/build/wallet/statemachine/verificationhash/EnterVerificationMessageBodyModel.kt",
    ),
    (
        "app/ui/features/public/src/commonTest/kotlin/build/wallet/statemachine/verificationhash/AddressAttestationUiStateMachineImplTests.kt",
        "app/ui/features/public/src/commonTest/kotlin/build/wallet/statemachine/verificationhash/AddressVerificationHashUiStateMachineImplTests.kt",
    ),
    # Rust WCA
    (
        "app/rust/wca/src/commands/sign_address_attestation.rs",
        "app/rust/wca/src/commands/sign_address_verification_hash.rs",
    ),
    # Firmware
    (
        "firmware/app/tasks/key_manager/src/w3-core/address_attestation.c",
        "firmware/app/tasks/key_manager/src/w3-core/address_verification_hash.c",
    ),
    (
        "firmware/app/tasks/key_manager/inc-private/address_attestation_impl.h",
        "firmware/app/tasks/key_manager/inc-private/address_verification_hash_impl.h",
    ),
]


def excluded(path: Path) -> bool:
    s = str(path)
    return any(x in s for x in EXCLUDE_PATH_SUBSTRINGS)


def git_mv(src: str, dst: str) -> None:
    src_p = ROOT / src
    dst_p = ROOT / dst
    if not src_p.exists():
        if dst_p.exists():
            print(f"skip mv (already at dest): {dst}")
            return
        print(f"WARN missing src: {src}", file=sys.stderr)
        return
    dst_p.parent.mkdir(parents=True, exist_ok=True)
    subprocess.check_call(["git", "mv", str(src_p), str(dst_p)], cwd=ROOT)
    print(f"git mv {src} → {dst}")


def apply_replacements(text: str) -> str:
    for old, new in REPLACEMENTS:
        text = text.replace(old, new)
    return text


def is_address_file(path: Path, text: str) -> bool:
    if excluded(path):
        return False
    # Always include files under verificationhash / moved paths after dir move
    rel = str(path.relative_to(ROOT))
    if "/verificationhash/" in rel or "sign_address_verification_hash" in rel:
        return True
    if "/addressattest/" in rel or "/bitcoin/attestation/" in rel:
        return True
    return any(m in text for m in ADDRESS_MARKERS)


def rewrite_tree() -> int:
    changed = 0
    for dirpath, _, filenames in os.walk(ROOT):
        for name in filenames:
            path = Path(dirpath) / name
            if excluded(path):
                continue
            if path.suffix not in {
                ".kt",
                ".kts",
                ".rs",
                ".udl",
                ".c",
                ".h",
                ".proto",
                ".yaml",
                ".yml",
                ".py",
                ".md",
                ".txt",
                ".def",
            } and name not in {"meson.build", "CMakeLists.txt"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, IsADirectoryError):
                continue
            if not is_address_file(path, text):
                continue
            new = apply_replacements(text)
            if new != text:
                path.write_text(new, encoding="utf-8")
                changed += 1
                print(f"rewrite {path.relative_to(ROOT)}")
    return changed


def leftover_scan() -> list[str]:
    hits: list[str] = []
    patterns = [
        r"AddressAttestation",
        r"addressattest",
        r"BKAddressAttestation",
        r"signAddressAttestation",
        r"SignAddressAttestation",
        r"sign_address_attestation",
        r"address_attestation",
        r"HwAttestationSigner",
        r"FakeHwAttestationDigestSigner",
        r"AttestationEcdsaCrypto",
        r"AttestationMessage",
        r"WatchingAttestation",
        r"ADDRESS_ATTESTATION",
        r"mobile-address-attestation",
        r"confirm_address_attestation",
        r"bitcoin\.attestation",
        r"bitcoin/attestation",
    ]
    combined = re.compile("|".join(patterns))
    for dirpath, _, filenames in os.walk(ROOT):
        for name in filenames:
            path = Path(dirpath) / name
            if excluded(path):
                continue
            if path.suffix not in {".kt", ".rs", ".udl", ".c", ".h", ".proto", ".yaml", ".yml"} and name != "meson.build":
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, IsADirectoryError):
                continue
            if combined.search(text):
                hits.append(str(path.relative_to(ROOT)))
    return sorted(set(hits))


def main() -> int:
    os.chdir(ROOT)
    print("=== phase 1: directory moves ===")
    for src, dst in DIR_MOVES:
        git_mv(src, dst)

    print("=== phase 2: file moves ===")
    for src, dst in FILE_MOVES:
        git_mv(src, dst)

    print("=== phase 3: content rewrite ===")
    n = rewrite_tree()
    print(f"rewrote {n} files")

    print("=== phase 4: leftover scan ===")
    leftovers = leftover_scan()
    if leftovers:
        print("LEFTOVERS still matching old address-attestation identifiers:")
        for h in leftovers:
            print(f"  {h}")
        return 1
    print("no address-attestation leftovers in scoped tree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
