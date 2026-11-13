"""Locate the most likely vulnerable file(s) to show the patch generator.

Best-effort: scan the working copy for source files and rank them by signals in
the exploit response and by risky sink patterns. Returns a list of
(relative_path, snippet) candidates, most-likely first.
"""
from __future__ import annotations

from pathlib import Path

from ..ingest.normalize import ExploitResult

_RISKY = (
    "execute(", "executemany(", "cursor.execute", "f\"SELECT", "f'SELECT",
    "os.system(", "subprocess.", "eval(", "exec(", "pickle.loads",
    "render_template_string", "send_file(", "open(", "yaml.load(",
    "child_process", "innerHTML", "res.send(",
)
_SRC_EXT = {".py", ".js", ".ts", ".go", ".rb", ".php"}
_IGNORE = {"__pycache__", "node_modules", ".git", ".venv", "venv", "tests"}


def locate(red: ExploitResult, workdir: Path, max_files: int = 3, max_bytes: int = 6000) -> list[dict]:
    workdir = Path(workdir)
    scored: list[tuple[int, Path]] = []
    hint = (red.body or "").lower()
    for p in workdir.rglob("*"):
        if not p.is_file() or p.suffix not in _SRC_EXT:
            continue
        if any(part in _IGNORE for part in p.parts):
            continue
        try:
            text = p.read_text()
        except Exception:
            continue
        score = sum(text.count(sig) for sig in _RISKY)
        if p.name in ("main.py", "app.py", "app.js", "server.js", "index.js"):
            score += 2
        # Traceback filename reflected in the response raises the score.
        if p.name.lower() in hint:
            score += 5
        if score:
            scored.append((score, p))
    scored.sort(key=lambda t: t[0], reverse=True)
    out: list[dict] = []
    for _, p in scored[:max_files]:
        rel = p.relative_to(workdir).as_posix()
        out.append({"path": rel, "content": p.read_text()[:max_bytes]})
    if not out:
        # Fallback to the entrypoint-ish file so the generator still has context.
        for name in ("main.py", "app.py", "app.js", "server.js", "index.js"):
            cand = next((q for q in workdir.rglob(name)), None)
            if cand:
                out.append({"path": cand.relative_to(workdir).as_posix(),
                            "content": cand.read_text()[:max_bytes]})
                break
    return out
