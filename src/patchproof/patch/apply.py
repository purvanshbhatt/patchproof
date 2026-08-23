"""Apply and rollback unified diffs against a target source tree.

Strategy:
- Use `git apply --whitespace=fix` when the tree is a git repo (preferred).
- Fall back to a hand-rolled diff applier that handles single-file @@ hunks.
- Rollback uses `git checkout -- .` when inside a repo, otherwise we restore
  snapshots taken before each apply.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Snapshot:
    """In-memory snapshot of a directory's text files for rollback."""
    files: dict[Path, bytes] = field(default_factory=dict)


def _is_git_repo(path: Path) -> bool:
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=path,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return r.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def _text_files(root: Path) -> Iterable[Path]:
    skip = {"__pycache__", ".git", "node_modules", ".venv", "dist", "build", ".egg-info"}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in skip for part in p.parts):
            continue
        try:
            p.read_bytes()
        except Exception:  # noqa: BLE001
            continue
        yield p


def snapshot(app_path: Path) -> Snapshot:
    snap = Snapshot()
    for p in _text_files(app_path):
        snap.files[p] = p.read_bytes()
    return snap


def restore(app_path: Path, snap: Snapshot) -> None:
    """Restore every file in the snapshot. Files created since are not removed."""
    for p, data in snap.files.items():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)


def _apply_with_git(app_path: Path, diff_text: str) -> bool:
    if not _is_git_repo(app_path):
        return False
    r = subprocess.run(
        ["git", "apply", "--whitespace=fix", "-"],
        cwd=app_path,
        input=diff_text,
        text=True,
        capture_output=True,
        timeout=15,
    )
    return r.returncode == 0


# ---------------------------------------------------------------------------
# Minimal unified-diff applier for single-file, plain-text hunks.
# Handles `--- a/path` / `+++ b/path` and `@@ -a,b +c,d @@` blocks.
# Good enough for the skeleton + hardcoded patch path; falls through cleanly.
# ---------------------------------------------------------------------------

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", re.MULTILINE)


def _split_diff(diff_text: str) -> list[tuple[str, list[str]]]:
    """Split a multi-file diff into [(path, [diff lines for that file]), ...]."""
    files: list[tuple[str, list[str]]] = []
    cur_path: str | None = None
    cur_lines: list[str] = []
    for raw in diff_text.splitlines(keepends=True):
        if raw.startswith("--- "):
            continue
        if raw.startswith("+++ "):
            path = raw[4:].strip().split("\t", 1)[0]
            path = path.removeprefix("b/")
            if cur_path is not None and cur_lines:
                files.append((cur_path, cur_lines))
            cur_path = path
            cur_lines = []
            continue
        if cur_path is not None:
            cur_lines.append(raw)
    if cur_path is not None and cur_lines:
        files.append((cur_path, cur_lines))
    return files


def _parse_hunks(lines: list[str]) -> list[tuple[int, int, list[str]]]:
    """Parse diff lines into [(old_start0, old_count, body_lines), ...].

    old_start0 is 0-indexed. body_lines keep their +/-/' ' tags.
    """
    hunks: list[tuple[int, int, list[str]]] = []
    i = 0
    while i < len(lines):
        m = _HUNK_RE.match(lines[i])
        if not m:
            i += 1
            continue
        old_start = int(m.group(1)) - 1
        old_count = int(m.group(2) or "1")
        body: list[str] = []
        i += 1
        seen = 0
        while i < len(lines):
            line = lines[i]
            if line.startswith("@@"):
                break
            tag = line[:1]
            if tag == "+":
                body.append(line)
                i += 1
                continue
            if tag == "\\":
                body.append(line)
                i += 1
                continue
            if seen >= old_count:
                break  # hunk body already consumed all original lines
            if tag in (" ", "-"):
                body.append(line)
                seen += 1
                i += 1
                continue
            if line.strip() == "":
                # tolerate blank context lines stripped of their leading space
                body.append(" \n" if not line.endswith("\n") else " " + line)
                seen += 1
                i += 1
                continue
            break
        hunks.append((old_start, old_count, body))
    return hunks


def _apply_file_patch(text: str, lines: list[str]) -> str | None:
    """Apply all hunks in `lines` to `text`. Returns new text or None on mismatch."""
    out_lines = text.splitlines(keepends=True)
    result: list[str] = []
    cursor = 0  # 0-indexed into out_lines
    ok = True

    for old_start, old_count, body in _parse_hunks(lines):
        # Copy unchanged region before this hunk.
        result.extend(out_lines[cursor:old_start])
        cursor = old_start

        consumed = 0
        for line in body:
            tag = line[:1]
            content = line[1:]
            if tag == " " or (tag == "" and content == "\n"):
                # Context: must match.
                if cursor >= len(out_lines) or out_lines[cursor] != content:
                    ok = False
                    break
                result.append(out_lines[cursor])
                cursor += 1
                consumed += 1
            elif tag == "-":
                if cursor >= len(out_lines) or out_lines[cursor] != content:
                    ok = False
                    break
                cursor += 1  # delete: skip original line
                consumed += 1
            elif tag == "+":
                result.append(content)
            elif tag == "\\":  # "\ No newline at end of file"
                pass
            else:
                break
        if not ok:
            return None
        # Sanity: we should have consumed exactly old_count original lines.
        if consumed != old_count:
            return None

    result.extend(out_lines[cursor:])
    return "".join(result)


def _apply_manual(app_path: Path, diff_text: str) -> bool:
    files = _split_diff(diff_text)
    if not files:
        return False
    success = True
    for relpath, lines in files:
        target = app_path / relpath
        if not target.exists():
            success = False
            break
        original = target.read_text()
        updated = _apply_file_patch(original, lines)
        if updated is None:
            success = False
            break
        target.write_text(updated)
    return success


def apply_diff(app_path: Path, diff_text: str) -> bool:
    """Apply a unified diff to the source tree. Returns True on success."""
    if not diff_text or not diff_text.strip():
        return False
    if _apply_with_git(app_path, diff_text):
        return True
    return _apply_manual(app_path, diff_text)


def rollback(app_path: Path, snap: Snapshot | None = None) -> None:
    """Revert the source tree. If a snapshot is given, restore from it.

    Otherwise, attempt `git checkout -- .` when inside a git repo.
    """
    if snap is not None:
        restore(app_path, snap)
        return
    if _is_git_repo(app_path):
        subprocess.run(
            ["git", "checkout", "--", "."],
            cwd=app_path,
            capture_output=True,
            check=False,
        )


__all__ = ["Snapshot", "apply_diff", "restore", "rollback", "snapshot"]


def _smoke_check() -> None:  # pragma: no cover
    if shutil.which("git"):
        return
