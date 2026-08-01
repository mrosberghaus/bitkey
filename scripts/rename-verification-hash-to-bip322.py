#!/usr/bin/env python3
"""Rename NFC/firmware/flag/settings verification-hash → BIP-322 (one-shot lever).

Does NOT rewrite domain verificationhash types (deleted/migrated separately) or UI
state machines (rewritten under proveaddress). Safe to re-run.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EXCLUDE_PATH_SUBSTRINGS = (
    "/server/",
    "/_build/",
    "/target/",
    "/.git/",
    "node_modules/",
    "rename-verification-hash-to-bip322.py",
    "rename-address-attestation-to-verification-hash.py",
    # Domain packages handled surgically
    "/bitcoin/verificationhash/",
    "/bitcoin/bip322/",
    "/statemachine/verificationhash/",
    "/statemachine/proveaddress/",
)

MARKERS = (
    "VerificationHash",
    "signAddressVerificationHash",
    "SignAddressVerificationHash",
    "sign_address_verification_hash",
    "address_verification_hash",
    "FakeHwVerificationHash",
    "ADDRESS_VERIFICATION_HASH",
    "mobile-verification-hash",
    "confirm_address_verification_hash",
    "CONFIRMATION_TYPE_SIGN_ADDRESS_VERIFICATION_HASH",
    "IPC_PROTO_SIGN_ADDRESS_VERIFICATION_HASH",
    "AddressVerificationHashUi",
    "fakeHwAttestationDigestSigner",
)

REPLACEMENTS: list[tuple[str, str]] = [
    # NFC Kotlin / FFI
    ("FakeHwVerificationHashDigestSignerImpl", "FakeHwBip322SighashSignerImpl"),
    ("FakeHwVerificationHashDigestSignerStub", "FakeHwBip322SighashSignerStub"),
    ("FakeHwVerificationHashDigestSignerUnsupported", "FakeHwBip322SighashSignerUnsupported"),
    ("FakeHwVerificationHashDigestSigner", "FakeHwBip322SighashSigner"),
    ("fakeHwAttestationDigestSigner", "fakeHwBip322SighashSigner"),
    ("signAddressVerificationHash", "signBip322Sighash"),
    ("SignAddressVerificationHashResultState", "SignBip322SighashResultState"),
    ("SignAddressVerificationHashResult", "SignBip322SighashResult"),
    ("SignAddressVerificationHash", "SignBip322Sighash"),
    ("HardwareConfirmationContent.AddressVerificationHash", "HardwareConfirmationContent.ProveAddress"),
    ("NfcEventTrackerScreenIdContext.ADDRESS_VERIFICATION_HASH", "NfcEventTrackerScreenIdContext.BIP322_SIGHASH"),
    ("ADDRESS_VERIFICATION_HASH", "BIP322_SIGHASH"),
    # Settings / flag / analytics wiring (not domain service)
    ("AddressVerificationHashUiStateMachineImpl", "ProveAddressUiStateMachineImpl"),
    ("AddressVerificationHashUiStateMachine", "ProveAddressUiStateMachine"),
    ("AddressVerificationHashUiProps", "ProveAddressUiProps"),
    ("build.wallet.statemachine.verificationhash", "build.wallet.statemachine.proveaddress"),
    ("VerificationHashEventTrackerScreenId", "ProveAddressEventTrackerScreenId"),
    ("VerificationHashFeatureFlag", "ProveAddressFeatureFlag"),
    ("verificationHashFeatureFlag", "proveAddressFeatureFlag"),
    ("verificationHashEnabled", "proveAddressEnabled"),
    ("addressVerificationHashUiStateMachine", "proveAddressUiStateMachine"),
    ("ShowingVerificationHashUiState", "ShowingProveAddressUiState"),
    ("SettingsListRow.VerificationHash", "SettingsListRow.ProveAddress"),
    ("SettingsAppSegment.VerificationHash", "SettingsAppSegment.ProveAddress"),
    ("object VerificationHash", "object ProveAddress"),
    ("data class VerificationHash", "data class ProveAddress"),
    ("VerificationHash::class", "ProveAddress::class"),
    ("is VerificationHash ->", "is ProveAddress ->"),
    ("is VerificationHash ", "is ProveAddress "),
    ("mobile-verification-hash-enabled", "mobile-prove-address-enabled"),
    (
        "Enables Settings entry to prove ownership of a used address with a Bitkey verification hash",
        "Enables Settings entry to prove ownership of a used address with a BIP-322 signature",
    ),
    ('title = "Verification hash"', 'title = "Prove address"'),
    ("verification-hash-nfc", "prove-address-nfc"),
    ('ScreenStateMachineMock<AddressVerificationHashUiProps>("verification-hash")',
     'ScreenStateMachineMock<ProveAddressUiProps>("prove-address")'),
    ("Attestation digest must be 32 bytes", "BIP-322 sighash must be 32 bytes"),
    # Firmware / WCA / proto
    ("sign_address_verification_hash_cmd", "sign_bip322_sighash_cmd"),
    ("sign_address_verification_hash_rsp", "sign_bip322_sighash_rsp"),
    ("sign_address_verification_hash_result", "sign_bip322_sighash_result"),
    ("sign_address_verification_hash", "sign_bip322_sighash"),
    ("SignAddressVerificationHashCmd", "SignBip322SighashCmd"),
    ("confirm_address_verification_hash", "confirm_bip322_sighash"),
    (
        "display_params_privileged_action_confirm_address_verification_hash",
        "display_params_privileged_action_confirm_bip322_sighash",
    ),
    ("address_verification_hash_impl", "bip322_sighash_impl"),
    ("address_verification_hash_session_t", "bip322_sighash_session_t"),
    ("address_verification_hash_clear_session", "bip322_sighash_clear_session"),
    ("address_verification_hash_handle_init", "bip322_sighash_handle_init"),
    ("address_verification_hash_register_handlers", "bip322_sighash_register_handlers"),
    ("address_verification_hash", "bip322_sighash"),
    ("CONFIRMATION_TYPE_SIGN_ADDRESS_VERIFICATION_HASH", "CONFIRMATION_TYPE_SIGN_BIP322_SIGHASH"),
    ("IPC_PROTO_SIGN_ADDRESS_VERIFICATION_HASH_CMD", "IPC_PROTO_SIGN_BIP322_SIGHASH_CMD"),
    ("IPC_PROTO_SIGN_ADDRESS_VERIFICATION_HASH", "IPC_PROTO_SIGN_BIP322_SIGHASH"),
]


def should_skip(path: Path) -> bool:
    return any(x in str(path) for x in EXCLUDE_PATH_SUBSTRINGS)


def iter_files() -> list[Path]:
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        # Do not prune package dir `build` (Kotlin sources live under build/wallet/...).
        dirnames[:] = [
            d
            for d in dirnames
            if d not in {".git", "node_modules", "target", "_build"}
        ]
        for name in filenames:
            p = Path(dirpath) / name
            if should_skip(p):
                continue
            if p.suffix in {
                ".kt", ".kts", ".rs", ".udl", ".proto", ".c", ".h", ".py",
                ".md", ".toml", ".txt", ".json",
            } or name in {"meson.build", "CMakeLists.txt"}:
                out.append(p)
    return out


def main() -> int:
    changed = 0
    for path in iter_files():
        try:
            raw = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, IsADirectoryError):
            continue
        if not any(m in raw for m in MARKERS):
            continue
        new = raw
        for old, repl in REPLACEMENTS:
            new = new.replace(old, repl)
        if new != raw:
            path.write_text(new, encoding="utf-8")
            changed += 1
            print(f"updated {path.relative_to(ROOT)}")
    print(f"content-updated files: {changed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
