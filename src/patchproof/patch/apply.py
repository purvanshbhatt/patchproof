"""Apply and roll back unified diffs on a working copy, backed by git.

The working copy is a throwaway git repo: a baseline commit is made at setup,
patches are applied with `git apply`, and rollback is a hard reset to baseline.
The user's original source tree is never modified.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

_IGNORE = {".git", "__pycache__", "node_modules", ".venv", "venv", "patchproof-out"}


def _git(workdir: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(workdir), *args],
                          capture_output=True, text=True, check=check)


@dataclass
class WorkCopy:
    """A git-backed copy of the target app."""

    src: Path
    dest: Path

    def setup(self) -> Path:
        self.src = Path(self.src)
        self.dest = Path(self.dest)
        if self.dest.exists():
            shutil.rmtree(self.dest)
        shutil.copytree(self.src, self.dest, ignore=shutil.ignore_patterns(*_IGNORE))
        _git(self.dest, "init", "-q")
        _git(self.dest, "config", "user.email", "patchproof@local")
        _git(self.dest, "config", "user.name", "patchproof")
        _git(self.dest, "add", "-A")
        _git(self.dest, "commit", "-q", "-m", "baseline", "--allow-empty")
        return self.dest


def apply_diff(workdir: Path, diff_text: str) -> bool:
    """Apply a unified diff. Tries several -p strip levels and whitespace-tolerant
    modes. Returns True iff the tree changed."""
    workdir = Path(workdir)
    if not diff_text.strip():
        return False
    diff_file = workdir / ".patchproof.diff"
    text = diff_text if diff_text.endswith("\n") else diff_text + "\n"
    diff_file.write_text(text)
    try:
        for extra in (["-p1"], ["-p0"], ["-p1", "--ignore-whitespace"]):
            r = _git(workdir, "apply", *extra, "--whitespace=nowarn", ".patchproof.diff", check=False)
            if r.returncode == 0:
                break
        else:
            # Last resort: GNU patch.
            r2 = subprocess.run(["patch", "-p1", "-i", ".patchproof.diff"],
                                cwd=str(workdir), capture_output=True, text=True)
            if r2.returncode != 0:
                return False
    finally:
        diff_file.unlink(missing_ok=True)
    status = _git(workdir, "status", "--porcelain", check=False).stdout.strip()
    return bool(status)


def rollback(workdir: Path) -> None:
    """Discard all uncommitted changes, back to the baseline commit."""
    workdir = Path(workdir)
    _git(workdir, "checkout", "-q", "--", ".", check=False)
    _git(workdir, "clean", "-fdq", check=False)


def diff_against_baseline(workdir: Path) -> str:
    """Return the current tree's diff vs baseline (the effective patch)."""
    return _git(Path(workdir), "diff", "HEAD", check=False).stdout
