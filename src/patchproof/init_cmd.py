"""Scaffold a patchproof.toml in the target directory."""
from pathlib import Path

import typer

TEMPLATE = """# patchproof configuration
[app]
# path = "./"

[poc]
# path = "./poc.py"

[patch]
max_attempts = 5
model = "gpt-4o-mini"

[regression]
# command = "pytest -q"
# command = "npm test --silent"
"""


def scaffold(directory: Path) -> None:
    target = directory / "patchproof.toml"
    if target.exists():
        typer.echo(f"already exists: {target}")
        raise typer.Exit(code=1)
    target.write_text(TEMPLATE)
    typer.echo(f"created {target}")
