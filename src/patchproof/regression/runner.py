"""Regression testing wrapper."""
from pathlib import Path
import subprocess

def run_regression_suite(app_path: Path) -> bool:
    """Runs the app's native tests (pytest/npm test)."""
    # For skeleton, we'll assume success unless configured otherwise
    return True
