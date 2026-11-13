import os

import httpx

BASE = os.environ["PATCHPROOF_BASE_URL"].rstrip("/")


def test_legit_read_preserved():
    r = httpx.get(BASE + "/read?file=readme.txt", timeout=10)
    assert r.status_code == 200
    assert "root:x:0:0" not in r.text
    assert "hello from patchproof fixture" in r.text
