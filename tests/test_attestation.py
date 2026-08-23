"""Tests for attestation writing/verification."""
from __future__ import annotations

from pathlib import Path

import pytest

from patchproof.report.attestation import (
    Attestation,
    load_attestation,
    sign_attestation,
    verify_signature,
    write_attestation,
)


def _key():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:  # pragma: no cover
        pytest.skip("cryptography not installed")
    return Ed25519PrivateKey.generate()


def test_write_load_roundtrip(tmp_path: Path) -> None:
    att = Attestation(target_sha="abc", poc_sha="def", attempts=3, model="gpt-4o-mini", verdict="green")
    p = tmp_path / "a.json"
    write_attestation(att, p)
    loaded = load_attestation(p)
    assert loaded.verdict == "green"
    assert loaded.attempts == 3


def test_sign_and_verify(tmp_path: Path) -> None:
    key = _key()
    att = Attestation(target_sha="a", poc_sha="b", attempts=1, model="m", verdict="green")
    sign_attestation(att, key)
    assert att.signature and att.signature["alg"] == "ed25519"
    assert verify_signature(att, key.public_key())
    # tamper
    att.attempts = 99
    assert not verify_signature(att, key.public_key())
