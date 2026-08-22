"""PoC ingestion + normalization."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

import httpx


@dataclass
class PoC:
    kind: str  # "http" | "python" | "nuclei" | "curl"
    payload: dict = field(default_factory=dict)  # method/url/headers/body or command
    success_predicate: Callable[[httpx.Response], bool] = field(default=lambda r: False)

    def sha256(self) -> str:
        return hashlib.sha256(
            json.dumps(self.payload, sort_keys=True).encode()
        ).hexdigest()

    def run(self, base_url: str, timeout: float = 5.0) -> "PoCResult":
        url = self.payload.get("url", "")
        if not url.startswith("http"):
            url = base_url.rstrip("/") + url
        method = self.payload.get("method", "GET").upper()
        headers = self.payload.get("headers", {})
        body = self.payload.get("body")
        with httpx.Client(timeout=timeout) as client:
            resp = client.request(method, url, headers=headers, content=body)
        return PoCResult(
            request={
                "method": method,
                "url": url,
                "headers": headers,
                "body": body,
            },
            response_status=resp.status_code,
            response_text=resp.text,
            response_headers=dict(resp.headers),
            exploit_succeeded=self.success_predicate(resp),
        )


@dataclass
class PoCResult:
    request: dict
    response_status: int
    response_text: str
    response_headers: dict
    exploit_succeeded: bool
    raw_response: str = ""

    def __post_init__(self) -> None:
        self.raw_response = (
            f"HTTP {self.response_status}\n"
            + "\n".join(f"{k}: {v}" for k, v in self.response_headers.items())
            + "\n\n"
            + self.response_text
        )

    def as_json(self) -> str:
        return json.dumps(
            {
                "request": self.request,
                "response_status": self.response_status,
                "response_text": self.response_text[:4000],
                "response_headers": dict(self.response_headers),
                "exploit_succeeded": self.exploit_succeeded,
            },
            indent=2,
        )


def _default_predicate(needle: str) -> Callable[[httpx.Response], bool]:
    def _p(r: httpx.Response) -> bool:
        if r.status_code >= 500:
            return True
        return needle.lower() in r.text.lower()
    return _p


def _parse_curl(text: str) -> dict:
    """Minimal curl parser: handles `curl -X POST URL [-d 'body'] [-H 'k: v']`."""
    args = re.findall(r"""('[^']*'|"[^"]*"|\S+)""", text)
    if args and args[0] == "curl":
        args = args[1:]
    method = "GET"
    url = ""
    headers: dict[str, str] = {}
    body: Optional[str] = None
    i = 0
    while i < len(args):
        a = args[i].strip("'\"")
        if a in ("-X", "--request"):
            method = args[i + 1].strip("'\"")
            i += 2
        elif a in ("-H", "--header"):
            kv = args[i + 1].strip("'\"")
            if ":" in kv:
                k, v = kv.split(":", 1)
                headers[k.strip()] = v.strip()
            i += 2
        elif a in ("-d", "--data", "--data-raw"):
            body = args[i + 1].strip("'\"")
            if method == "GET":
                method = "POST"
            i += 2
        elif a.startswith("-"):
            i += 2 if i + 1 < len(args) else 1
        else:
            url = a
            i += 1
    return {"method": method, "url": url, "headers": headers, "body": body}


def _detect(text: str) -> tuple[str, dict, Callable]:
    s = text.strip()
    if s.startswith("curl "):
        parsed = _parse_curl(s)
        return "curl", parsed, _default_predicate("error")
    if s.startswith("GET ") or s.startswith("POST ") or s.startswith("PUT ") or s.startswith("DELETE "):
        # raw HTTP request line
        lines = s.splitlines()
        parts = lines[0].split(" ")
        method, path = parts[0], parts[1]
        headers: dict[str, str] = {}
        body_start = len(lines)
        for idx, line in enumerate(lines[1:], start=1):
            if not line.strip():
                body_start = idx + 1
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        body = "\n".join(lines[body_start:]) if body_start < len(lines) else None
        return "http", {"method": method, "url": path, "headers": headers, "body": body}, _default_predicate("error")
    if s.startswith("{") and '"nuclei"' in s.lower():
        # nuclei template — coarse parse
        try:
            data = json.loads(s)
            reqs = data.get("requests", [])
            if reqs:
                r0 = reqs[0]
                method = (r0.get("method") or "GET").upper()
                path = r0.get("path") or ["/"][0]
                matchers = r0.get("matchers", [])
                needle = ""
                for m in matchers:
                    if m.get("type") == "word":
                        words = m.get("words") or m.get("raw") or []
                        if words:
                            needle = words[0]
                            break
                    if m.get("type") == "status":
                        return "nuclei", {"method": method, "url": path, "headers": {}, "body": None}, \
                            (lambda code=int(m.get("status", [200])[0]): (lambda r: r.status_code == code))()
                return "nuclei", {"method": method, "url": path, "headers": {}, "body": None}, _default_predicate(needle or "error")
        except Exception:
            pass
    # fallback: python
    return "python", {"script": s}, _default_predicate("error")


def load_poc(path: Path) -> PoC:
    """Load a PoC from disk and return a normalized PoC object."""
    text = path.read_text()
    kind, payload, predicate = _detect(text)
    return PoC(kind=kind, payload=payload, success_predicate=predicate)
