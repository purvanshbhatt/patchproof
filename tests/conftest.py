"""Shared pytest configuration."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def docker_available() -> bool:
    return shutil.which("docker") is not None


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture(scope="session")
def docker_ready() -> bool:
    return docker_available()
