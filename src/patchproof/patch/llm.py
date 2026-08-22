"""LLM patch generation."""
from typing import Optional
from ..ingest.normalize import PoC

def generate_patch(target: str, poc: PoC, red_response: str, model: str) -> str:
    """
    Call LiteLLM to generate a unified diff.
    In skeleton mode, this will be a stub returning an empty diff or a dummy.
    """
    # In skeleton mode, we rely on the hardcoded_patch flag in pipeline.py
    return ""
