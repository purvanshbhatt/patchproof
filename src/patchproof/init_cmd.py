"""Scaffold a patchproof.toml in the target directory."""
from pathlib import Path

import typer

TEMPLATE = """# patchproof configuration
[app]
# path = "./app"

[poc]
# path = "./poc.txt"

[patch]
max_attempts = 5
model = "anthropic/claude-sonnet-4-5"

[sandbox]
# runner = "auto"   # auto | local | docker
"""


def scaffold(directory: Path) -> None:
    target = Path(directory) / "patchproof.toml"
    if target.exists():
        typer.echo(f"already exists: {target}")
        raise typer.Exit(code=1)
    target.write_text(TEMPLATE)
    typer.echo(f"created {target}")
