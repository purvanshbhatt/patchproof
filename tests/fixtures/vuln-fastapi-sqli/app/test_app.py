import os

import httpx

BASE = os.environ["PATCHPROOF_BASE_URL"].rstrip("/")


def test_legit_request_preserved():
    r = httpx.get(BASE + "/?id=1", timeout=10)
    assert r.status_code == 200
    assert "EXPLOIT_LEAK" not in r.text
