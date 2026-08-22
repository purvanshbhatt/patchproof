"""Patch location and graph logic."""
from pathlib import Path
from typing import Optional
from ..ingest.normalize import PoCResult

def locate(red_result: PoCResult, app_path: Path) -> str:
    """
    Finds the most likely vulnerable file:line.
    In the skeleton, we'll return a guessed path based on the response.
    """
    # Real implementation will use tree-sitter + stack trace parsing
    if "SQL" in red_text := red_result.response_text.upper():
        return "app/main.py:12"
    return "app/main.py:1"
