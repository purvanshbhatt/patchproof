"""Tests for PoC ingestion + normalization."""
from __future__ import annotations

from pathlib import Path

from patchproof.ingest.normalize import load_poc


def test_parse_curl(tmp_path: Path) -> None:
    p = tmp_path / "poc.txt"
    p.write_text("""curl -X POST 'http://target.example/api' -H 'Content-Type: application/json' -d '{"q":"x"}'""")
    poc = load_poc(p)
    assert poc.kind == "curl"
    assert poc.payload["method"] == "POST"
    assert poc.payload["url"] == "http://target.example/api"
    assert poc.payload["headers"]["Content-Type"] == "application/json"
    assert poc.payload["body"] == '{"q":"x"}'


def test_parse_http_raw(tmp_path: Path) -> None:
    p = tmp_path / "poc.txt"
    p.write_text("GET /api?x=1 HTTP/1.1\nHost: target.example\n\nbody")
    poc = load_poc(p)
    assert poc.kind == "http"
    assert poc.payload["method"] == "GET"
    assert poc.payload["url"] == "/api?x=1"
    assert poc.payload["headers"]["Host"] == "target.example"


def test_parse_python_fallback(tmp_path: Path) -> None:
    p = tmp_path / "poc.txt"
    p.write_text("import httpx; print('EXPLOIT_OK')")
    poc = load_poc(p)
    assert poc.kind == "python"


def test_parse_nuclei(tmp_path: Path) -> None:
    payload = """{
      "id": "test",
      "info": {"name": "test"},
      "requests": [
        {"method": "get", "path": ["/admin"], "matchers": [{"type": "status", "status": [403]}]}
      ]
    }"""
    p = tmp_path / "poc.txt"
    p.write_text(payload)
    poc = load_poc(p)
    assert poc.kind == "nuclei"
    assert poc.payload["url"] == "/admin"
