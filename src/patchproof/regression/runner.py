"""Regression testing wrapper.

Executes the application's native test suite inside the running sandbox
container via `docker exec`. Supports Python (pytest) and Node (npm test).
"""
from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

from ..sandbox.app_spec import AppSpec


def run_tests(container_name: str, spec: AppSpec, cwd: Path | None = None) -> bool:
    """Run the framework test suite in the container. Returns True on success."""
    cmd = ["docker", "exec", container_name, "sh", "-c", spec.test_cmd]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except subprocess.TimeoutExpired:
        return False
    return proc.returncode == 0


def run_command(container_name: str, shell_cmd: str) -> subprocess.CompletedProcess[str]:
    """Lower-level helper: run an arbitrary shell command inside the container."""
    return subprocess.run(
        ["docker", "exec", container_name, "sh", "-c", shell_cmd],
        capture_output=True,
        text=True,
        timeout=120,
    )


def collect_logs(container_name: str, tail: int = 200) -> str:
    """Best-effort retrieval of recent container logs."""
    try:
        proc = subprocess.run(
            ["docker", "logs", "--tail", str(tail), container_name],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return (proc.stdout or "") + (proc.stderr or "")
    except Exception:  # noqa: BLE001
        return ""


__all__ = ["collect_logs", "run_command", "run_tests"]


def _unused() -> str:  # pragma: no cover
    return shlex.quote("placeholder")
