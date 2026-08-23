"""Attestation writer.

Schema (JSON):
    {
      "target_sha": "<sha256 of source tree>",
      "poc_sha":    "<sha256 of normalized PoC>",
      "attempts":   <int>,
      "model":      "<model id or 'hardcoded'>",
      "verdict":    "green" | "red" | "still_red" | "regression" | "not_exploitable",
      "timestamp":  "<iso8601>",
      "signature":  {
        "alg":  "ed25519",
        "key_id": "<sha256 of pubkey>",
        "value": "<base64 signature over canonical JSON>"
      } or null
    }

Signing is optional. Pass `private_key=<ed25519 PrivateKey>` to sign.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Attestation:
    target_sha: str
    poc_sha: str
    attempts: int
    model: str
    verdict: str
    timestamp: str = field(default_factory=lambda: _dt.datetime.now(_dt.UTC).isoformat())
    signature: dict | None = None


def _canonical_json(data: dict) -> bytes:
    """Stable JSON for signing/verification."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def sign_attestation(att: Attestation, private_key: Any) -> None:
    """Sign the attestation in-place. `private_key` is a cryptography ed25519 key."""
    payload = asdict(att)
    payload.pop("signature", None)
    canon = _canonical_json(payload)
    sig = private_key.sign(canon)
    pub = private_key.public_key().public_bytes_raw()
    att.signature = {
        "alg": "ed25519",
        "key_id": hashlib.sha256(pub).hexdigest(),
        "value": base64.b64encode(sig).decode("ascii"),
    }


def write_attestation(att: Attestation, path: Path) -> None:
    path.write_text(json.dumps(asdict(att), indent=2, sort_keys=True))


def load_attestation(path: Path) -> Attestation:
    data = json.loads(path.read_text())
    return Attestation(**data)


def verify_signature(att: Attestation, public_key: Any) -> bool:
    if not att.signature:
        return False
    payload = asdict(att)
    payload.pop("signature", None)
    try:
        sig = base64.b64decode(att.signature["value"])
        public_key.verify(sig, _canonical_json(payload))
        return True
    except Exception:  # noqa: BLE001
        return False


__all__ = ["Attestation", "load_attestation", "sign_attestation", "verify_signature", "write_attestation"]
