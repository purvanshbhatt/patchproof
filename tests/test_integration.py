"""End-to-end: verify a known-good patch blocks the exploit, in the local runner.

Runs the real app in a subprocess venv, so it is slower; skipped if the network
is unavailable for dependency install."""
from pathlib import Path

import pytest

from patchproof.pipeline import verify_only

FIXTURES = Path(__file__).parent / "fixtures"


def _net_ok() -> bool:
    try:
        import httpx

        httpx.get("https://pypi.org/simple/pip/", timeout=5)
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _net_ok(), reason="no network for venv install")


@pytest.mark.parametrize("fixture", ["vuln-fastapi-sqli", "vuln-flask-pathtraversal"])
def test_good_patch_verifies(fixture, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    base = FIXTURES / fixture
    rc = verify_only(
        app_path=base / "app",
        poc=base / "poc.txt",
        patch_file=base / "fix.patch",
        runner_backend="local",
    )
    assert rc == 0
