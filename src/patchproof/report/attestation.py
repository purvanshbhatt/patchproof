"""Exploit-verified attestation.

Emits an in-toto Statement (v1) with a custom predicate
`patchproof/exploit-verified/v0.1`. The predicate records the PoC digest, the
pre-patch and post-patch exploit outcomes, variant-PoC results, and the
regression-test result. Labels are deliberately honest: a green run proves the
exploit (and its variants) is blocked and tests pass, NOT that the patch is
semantically correct. `semantic_review` is always "none" unless a human signs.

Optionally emits a companion OpenVEX document marking the vuln `fixed`.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

PREDICATE_TYPE = "https://patchproof.dev/attestation/exploit-verified/v0.1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"


@dataclass
class VariantOutcome:
    label: str
    blocked: bool


@dataclass
class ExploitVerifiedPredicate:
    tool: str
    tool_version: str
    timestamp: str
    poc_sha256: str
    poc_kind: str
    pre_patch_exploit_succeeded: bool
    post_patch_exploit_blocked: bool
    variants_total: int
    variants_blocked: int
    variant_results: list[VariantOutcome]
    regression_passed: bool
    regression_note: str
    runner: str
    model: str
    attempts: int
    semantic_review: str = "none"
    disclaimer: str = (
        "A green verdict proves the supplied exploit and its generated variants "
        "no longer succeed and the app's tests still pass. It does NOT prove the "
        "patch is semantically correct or complete; independent review of untested "
        "and variant-adjacent behavior is still required."
    )


@dataclass
class Attestation:
    subject_name: str
    subject_sha256: str
    predicate: ExploitVerifiedPredicate

    def to_statement(self) -> dict:
        return {
            "_type": STATEMENT_TYPE,
            "subject": [{"name": self.subject_name, "digest": {"sha256": self.subject_sha256}}],
            "predicateType": PREDICATE_TYPE,
            "predicate": asdict(self.predicate),
        }


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def tree_sha256(path: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(Path(path).rglob("*")):
        if p.is_file() and not any(x in p.parts for x in ("__pycache__", ".git", "node_modules", "venv", ".venv")):
            h.update(p.relative_to(path).as_posix().encode())
            h.update(p.read_bytes())
    return h.hexdigest()


def write_attestation(att: Attestation, path: Path) -> None:
    Path(path).write_text(json.dumps(att.to_statement(), indent=2, sort_keys=True))


def write_openvex(*, path: Path, vuln_id: str, product: str, status: str = "fixed") -> None:
    doc = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://patchproof.dev/vex/{int(time.time())}",
        "author": "patchproof",
        "timestamp": now_iso(),
        "version": 1,
        "statements": [
            {"vulnerability": {"name": vuln_id}, "products": [{"@id": product}], "status": status}
        ],
    }
    Path(path).write_text(json.dumps(doc, indent=2, sort_keys=True))
