"""Attestation and evidence writer."""
import json
from dataclasses import dataclass, asdict
from pathlib import Path

@dataclass
class Attestation:
    target_sha: str
    poc_sha: str
    attempts: int
    model: str
    verdict: str

def write_attestation(attest: Attestation, path: Path) -> None:
    path.write_text(json.dumps(asdict(attest), indent=2))
