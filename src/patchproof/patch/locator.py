"""Locate the vulnerable code site in the target tree.

Strategy:
1. Grep the source tree for the route referenced by the PoC payload.
2. If found, scan the enclosing function for sink patterns (raw SQL, eval,
   os.system, subprocess shell=True, request args flowing to sinks).
3. Fall back to "first file with a matching route" when static analysis fails.

The locator returns a precise `file:line` plus a small code window around it so
the LLM can craft a minimal diff.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..ingest.normalize import PoCResult


@dataclass
class PatchTarget:
    file: Path
    line: int
    snippet: str
    route: str = ""
    sink: str = ""

    def __str__(self) -> str:
        rel = self.file
        try:
            rel = self.file.relative_to(Path.cwd())
        except ValueError:
            pass
        return f"{rel}:{self.line}"


_SINK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("sql_concat", re.compile(r"""(execute|f"SELECT|f'SELECT|\bSELECT\s+.*\+|cursor\.execute\([^,]*%s|where\s+['\"]?\s*\+|text\(['\"]\s*SELECT)""")),
    ("sql_string_format", re.compile(r"""(\.execute\([^)]*%[^)]*\)|\.execute\(f['\"])""")),
    ("shell", re.compile(r"""\bos\.(system|popen)\(|\bsubprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True""")),
    ("eval", re.compile(r"""\beval\s*\(|\bexec\s*\(""")),
    ("deserialization", re.compile(r"""\b(pickle|yaml\.load|jsonpickle)\.(loads?|decode)\(""")),
]


def _route_from_poc(result: PoCResult) -> str:
    url = result.request.get("url", "")
    return url.split("?", 1)[0]


def _find_route_file(app_path: Path, route: str) -> Path | None:
    """Find the first source file that registers the given route."""
    needle_decorators = [
        re.compile(rf'@\s*\w+\.(get|post|put|delete|patch|route)\(\s*["\']{re.escape(route)}["\']'),
        re.compile(rf'\.(get|post|put|delete|patch)\(\s*["\']?{re.escape(route)}["\']?'),
    ]
    for p in app_path.rglob("*.py"):
        if "__pycache__" in str(p) or "node_modules" in str(p):
            continue
        try:
            text = p.read_text()
        except Exception:  # noqa: BLE001
            continue
        for pat in needle_decorators:
            if pat.search(text):
                return p
    return None


def _function_span(text: str, line_no: int) -> tuple[int, int]:
    """Return (start_line, end_line) of the function containing line_no (1-indexed)."""
    lines = text.splitlines()
    start = line_no - 1
    # walk up to find the `def` / `async def`
    while start >= 0 and not re.match(r"^\s*(async\s+def|def)\s", lines[start]):
        start -= 1
    if start < 0:
        return (line_no, line_no)
    # walk down to the next dedented line
    base_indent = len(lines[start]) - len(lines[start].lstrip())
    end = start + 1
    while end < len(lines):
        line = lines[end]
        if line.strip() == "":
            end += 1
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= base_indent:
            break
        end += 1
    return (start + 1, end)


def _best_sink_line(text: str, span: tuple[int, int]) -> tuple[int, str]:
    lines = text.splitlines()
    start, end = span
    for i in range(start - 1, min(end, len(lines))):
        line = lines[i]
        for name, pat in _SINK_PATTERNS:
            if pat.search(line):
                return i + 1, name
    # fallback: middle of the function
    return (start + end) // 2, "unknown"


def locate(red_result: PoCResult, app_path: Path) -> PatchTarget:
    """Find the most likely vulnerable site given the red PoC result."""
    route = _route_from_poc(red_result)
    py_file = _find_route_file(app_path, route)
    if py_file is None:
        # pick any python file
        for p in app_path.rglob("*.py"):
            if "__pycache__" not in str(p):
                py_file = p
                break
    if py_file is None:
        return PatchTarget(file=app_path, line=1, snippet="", route=route)

    text = py_file.read_text()
    # heuristic: sink line search inside the function that handles the route
    span = _function_span(text, 1)
    # if the route's decorator line is known, anchor on it
    decorator = re.search(rf'@\s*\w+\.(?:get|post|put|delete|patch)\(\s*["\']{re.escape(route)}', text)
    if decorator:
        line_no = text[: decorator.start()].count("\n") + 1
        span = _function_span(text, line_no + 1)
    sink_line, sink_name = _best_sink_line(text, span)

    lines = text.splitlines()
    lo = max(0, sink_line - 6)
    hi = min(len(lines), sink_line + 5)
    snippet = "\n".join(lines[lo:hi])

    return PatchTarget(file=py_file, line=sink_line, snippet=snippet, route=route, sink=sink_name)
