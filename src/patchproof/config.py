"""Load defaults from patchproof.toml (optional)."""
from __future__ import annotations

from pathlib import Path

try:
    import tomllib  # py311+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore


def load(directory: Path) -> dict:
    """Return a flat dict of overrides from patchproof.toml, or {}."""
    path = Path(directory) / "patchproof.toml"
    if not path.exists():
        return {}
    data = tomllib.loads(path.read_text())
    out: dict = {}
    if "app" in data and "path" in data["app"]:
        out["app"] = data["app"]["path"]
    if "poc" in data and "path" in data["poc"]:
        out["poc"] = data["poc"]["path"]
    patch = data.get("patch", {})
    if "max_attempts" in patch:
        out["max_attempts"] = patch["max_attempts"]
    if "model" in patch:
        out["model"] = patch["model"]
    sandbox = data.get("sandbox", {})
    if "runner" in sandbox:
        out["runner"] = sandbox["runner"]
    return out
