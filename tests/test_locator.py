"""Tests for the locator (no LLM, no Docker)."""
from __future__ import annotations

from pathlib import Path

from patchproof.ingest.normalize import PoCResult
from patchproof.patch.locator import locate


def _red(path: str = "/") -> PoCResult:
    return PoCResult(
        request={"method": "GET", "url": path, "headers": {}, "body": None},
        response_status=500,
        response_text="syntax error in SQL near 'OR'",
        response_headers={"content-type": "text/html"},
        exploit_succeeded=True,
    )


def test_locator_finds_fastapi_route(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI, Request\n"
        "app = FastAPI()\n"
        "\n"
        "@app.get('/users')\n"
        "async def users(request: Request):\n"
        "    q = request.query_params.get('id', '1')\n"
        '    if "OR" in q:\n'
        "        return f'select * from users where id={q}'\n"
        "    return []\n"
    )
    target = locate(_red("/users"), tmp_path)
    assert target.file.name == "main.py"
    assert target.line >= 5
    assert "OR" in target.snippet


def test_locator_fallback_unknown_file(tmp_path: Path) -> None:
    target = locate(_red("/never"), tmp_path)
    assert target.line >= 1
