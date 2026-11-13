"""End-to-end integration test against the FastAPI SQLi fixture.

Requires Docker on PATH. Marked as `integration` so it can be skipped in
container-less CI: `pytest -m 'not integration'`.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from patchproof.pipeline import verify_only

FIXTURE = Path(__file__).parent / "fixtures" / "vuln-fastapi-sqli"
APP = FIXTURE / "app"
POC = FIXTURE / "poc.txt"
PATCH = FIXTURE / "fix.patch"


pytestmark = pytest.mark.integration


def _docker() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(["docker", "info"], check=True, capture_output=True, timeout=10)
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _docker(), reason="docker daemon unavailable")
def test_hardcoded_patch_blocks_sqli() -> None:
    """The fixture patch must turn the red PoC into a green regression-safe state."""
    rc = verify_only(app_path=APP, poc=POC, patch_file=PATCH)
    assert rc == 0
