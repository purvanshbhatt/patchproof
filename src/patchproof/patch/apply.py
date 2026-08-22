"""Apply and rollback diffs."""
from pathlib import Path
import subprocess

def apply_diff(app_path: Path, diff_text: str) -> bool:
    """Applies a unified diff to the source tree."""
    if not diff_text.strip():
        return False
    try:
        # In a real setup, we'd write to a tmp file and use `git apply`
        # For skeleton, we simulate success if diff_text exists
        return True
    except Exception:
        return False

def rollback(app_path: Path) -> None:
    """Reverts changes to the source tree."""
    # Skeleton: assume git reset or similar
    pass
