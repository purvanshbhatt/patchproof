"""PoC ingestion, normalization, and variant generation.

A PoC is treated as *untrusted data*. Its text is never injected verbatim into
an LLM prompt (see patch.llm) and is never executed as a shell command on the
host. HTTP/curl/nuclei PoCs are replayed over the wire; python PoCs run inside
the sandbox runner, not on the host.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

import httpx

# Markers that, if reflected in a response body, indicate a successful exploit
# for the bundled fixtures and common leak-style PoCs. Case-insensitive.
DEFAULT_LEAK_MARKERS = ("EXPLOIT_LEAK", "admin_password", "root:x:0:0", "/etc/passwd")


@dataclass
class Oracle:
    """Decides whether a response proves the exploit worked.

    An exploit "succeeds" when ANY configured signal fires:
      - status code >= 500 (unhandled crash), when crash_is_success
      - status code equals an explicit expected_status
      - any marker string is present in the body
    """

    markers: tuple[str, ...] = DEFAULT_LEAK_MARKERS
    expected_status: int | None = None
    crash_is_success: bool = True

    def judge(self, status: int, body: str) -> bool:
        if self.expected_status is not None and status == self.expected_status:
            return True
        if self.crash_is_success and status >= 500:
            return True
        low = body.lower()
        return any(m.lower() in low for m in self.markers)


@dataclass
class ExploitResult:
    request: dict
    status: int
    body: str
    headers: dict
    succeeded: bool
    note: str = ""

    @property
    def raw_response(self) -> str:
        head = "\n".join(f"{k}: {v}" for k, v in self.headers.items())
        return f"HTTP {self.status}\n{head}\n\n{self.body}"

    def as_json(self) -> str:
        return json.dumps(
            {
                "request": self.request,
                "status": self.status,
                "body": self.body[:4000],
                "headers": dict(self.headers),
                "succeeded": self.succeeded,
                "note": self.note,
            },
            indent=2,
            sort_keys=True,
        )


@dataclass
class PoC:
    kind: str  # "http" | "curl" | "nuclei" | "python"
    payload: dict = field(default_factory=dict)
    oracle: Oracle = field(default_factory=Oracle)
    label: str = "base"

    def sha256(self) -> str:
        return hashlib.sha256(
            json.dumps({"kind": self.kind, "payload": self.payload}, sort_keys=True).encode()
        ).hexdigest()

    def _abs_url(self, base_url: str) -> str:
        url = self.payload.get("url", "/")
        if url.startswith("http://") or url.startswith("https://"):
            # Rehost onto the sandbox base_url; keep path + query only.
            parts = urlsplit(url)
            base = urlsplit(base_url)
            return urlunsplit((base.scheme, base.netloc, parts.path, parts.query, ""))
        return base_url.rstrip("/") + "/" + url.lstrip("/")

    def run_http(self, base_url: str, timeout: float = 10.0) -> ExploitResult:
        url = self._abs_url(base_url)
        method = self.payload.get("method", "GET").upper()
        headers = self.payload.get("headers", {})
        body = self.payload.get("body")
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                resp = client.request(method, url, headers=headers, content=body)
            succeeded = self.oracle.judge(resp.status_code, resp.text)
            return ExploitResult(
                request={"method": method, "url": url, "headers": headers, "body": body},
                status=resp.status_code,
                body=resp.text,
                headers=dict(resp.headers),
                succeeded=succeeded,
            )
        except httpx.RequestError as e:
            # A connection error is NOT a successful exploit; report it.
            return ExploitResult(
                request={"method": method, "url": url, "headers": headers, "body": body},
                status=0,
                body=str(e),
                headers={},
                succeeded=False,
                note="request_error",
            )

    def variants(self) -> list[PoC]:
        """Generate cheap payload variants (AIxCC-style variant PoVs) that a
        correct fix must also block. Over-fitted string blocks pass the base
        PoC but fail these. HTTP/curl only.
        """
        if self.kind not in ("http", "curl", "nuclei"):
            return []
        url = self.payload.get("url", "/")
        if "?" not in url:
            return []
        path, _, query = url.partition("?")
        out: list[PoC] = []

        def _mk(new_query: str, label: str) -> PoC:
            p = dict(self.payload)
            p["url"] = f"{path}?{new_query}"
            return PoC(kind=self.kind, payload=p, oracle=self.oracle, label=label)

        # 1. Upper/lower case flip of the query (defeats case-sensitive blocks).
        flipped = "".join(c.lower() if c.isupper() else c.upper() for c in query)
        if flipped != query:
            out.append(_mk(flipped, "case-flip"))
        # 2. URL-encode the single quotes (defeats literal "'" blocks).
        if "'" in query:
            out.append(_mk(query.replace("'", "%27"), "url-encoded-quote"))
        # 3. Inline comment splice for SQL-ish payloads.
        if " OR " in query.upper():
            out.append(_mk(re.sub(r"(?i) OR ", "/**/OR/**/", query), "comment-splice"))
        return out


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def _split_curl_args(text: str) -> list[str]:
    return re.findall(r"""'[^']*'|"[^"]*"|\S+""", text)


def _strip(tok: str) -> str:
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "'\"":
        return tok[1:-1]
    return tok


def _parse_curl(text: str) -> dict:
    args = _split_curl_args(text)
    if args and _strip(args[0]) == "curl":
        args = args[1:]
    method, url, body = "GET", "", None
    headers: dict[str, str] = {}
    i = 0
    while i < len(args):
        a = _strip(args[i])
        if a in ("-X", "--request") and i + 1 < len(args):
            method = _strip(args[i + 1])
            i += 2
        elif a in ("-H", "--header") and i + 1 < len(args):
            kv = _strip(args[i + 1])
            if ":" in kv:
                k, v = kv.split(":", 1)
                headers[k.strip()] = v.strip()
            i += 2
        elif a in ("-d", "--data", "--data-raw", "--data-binary") and i + 1 < len(args):
            body = _strip(args[i + 1])
            if method == "GET":
                method = "POST"
            i += 2
        elif a.startswith("-"):
            i += 1
        else:
            url = a
            i += 1
    return {"method": method, "url": url, "headers": headers, "body": body}


def _parse_raw_http(text: str) -> dict:
    lines = text.splitlines()
    method, path, *_ = (lines[0].split(" ") + ["", ""])[:3]
    headers: dict[str, str] = {}
    body_lines: list[str] = []
    in_body = False
    for line in lines[1:]:
        if in_body:
            body_lines.append(line)
        elif not line.strip():
            in_body = True
        elif ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    body = "\n".join(body_lines) if body_lines else None
    return {"method": method.upper(), "url": path, "headers": headers, "body": body}


def _parse_nuclei(text: str) -> tuple[dict, Oracle]:
    """Coarse Nuclei YAML/JSON parse: first request + first matcher."""
    import yaml  # pyyaml is a dependency

    data = yaml.safe_load(text)
    reqs = data.get("http") or data.get("requests") or []
    payload = {"method": "GET", "url": "/", "headers": {}, "body": None}
    oracle = Oracle()
    if reqs:
        r0 = reqs[0]
        payload["method"] = (r0.get("method") or "GET").upper()
        paths = r0.get("path") or ["/"]
        raw = paths[0] if isinstance(paths, list) else paths
        payload["url"] = raw.replace("{{BaseURL}}", "").replace("{{Hostname}}", "") or "/"
        markers: list[str] = []
        status: int | None = None
        for m in r0.get("matchers", []):
            if m.get("type") == "word":
                markers += m.get("words", [])
            elif m.get("type") == "status":
                codes = m.get("status", [])
                if codes:
                    status = int(codes[0])
        if markers:
            oracle = Oracle(markers=tuple(markers), expected_status=status)
        elif status is not None:
            oracle = Oracle(markers=(), expected_status=status, crash_is_success=False)
    return payload, oracle


def load_poc(path) -> PoC:
    """Load a PoC file and normalize it. Auto-detects curl / raw HTTP / nuclei /
    python. A leading `#patchproof:` directive line may override the oracle, e.g.

        #patchproof: marker=EXPLOIT_LEAK status=500
    """
    text = _read(path)
    oracle_override = _parse_directive(text)

    stripped = _strip_directive(text).strip()
    first = stripped.split("\n", 1)[0].strip()

    if first.startswith("curl"):
        payload = _parse_curl(stripped)
        return PoC("curl", payload, oracle_override or Oracle())
    if re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD) ", first):
        payload = _parse_raw_http(stripped)
        return PoC("http", payload, oracle_override or Oracle())
    if "requests" in stripped and "matchers" in stripped or first in ("id:", "info:"):
        try:
            payload, parsed_oracle = _parse_nuclei(stripped)
            return PoC("nuclei", payload, oracle_override or parsed_oracle)
        except Exception:
            pass
    return PoC("python", {"script": stripped}, oracle_override or Oracle())


def _read(path) -> str:
    try:
        return path.read_text()
    except AttributeError:
        with open(path) as f:
            return f.read()


_DIRECTIVE = re.compile(r"^#patchproof:\s*(.+)$", re.MULTILINE)


def _parse_directive(text: str) -> Oracle | None:
    m = _DIRECTIVE.search(text)
    if not m:
        return None
    markers: list[str] = []
    status: int | None = None
    crash = True
    for tok in m.group(1).split():
        if tok.startswith("marker="):
            markers.append(tok[len("marker="):])
        elif tok.startswith("status="):
            status = int(tok[len("status="):])
        elif tok == "no-crash":
            crash = False
    return Oracle(
        markers=tuple(markers) if markers else DEFAULT_LEAK_MARKERS,
        expected_status=status,
        crash_is_success=crash,
    )


def _strip_directive(text: str) -> str:
    return _DIRECTIVE.sub("", text)
