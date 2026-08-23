from pathlib import Path

import typer
from rich.console import Console

from . import __version__

app = typer.Typer(
    name="patchproof",
    help="Deterministic exploit repro + AI patch verification.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"patchproof {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """PatchProof CLI."""


@app.command()
def run(
    app_path: Path = typer.Option(..., "--app", help="Path to target app source."),
    poc: Path = typer.Option(..., "--poc", help="PoC exploit file or URL."),
    max_attempts: int = typer.Option(5, "--max-attempts", help="Max AI patch iterations."),
    model: str = typer.Option("gpt-4o-mini", "--model", help="LiteLLM model id."),
    out: Path = typer.Option(Path("patchproof-out"), "--out", help="Output directory."),
    hardcoded_patch: Path | None = typer.Option(
        None,
        "--hardcoded-patch",
        help="Skip LLM; apply this diff file and verify (skeleton mode).",
    ),
) -> None:
    """Run the full red→green loop against a target app."""
    from .pipeline import Pipeline

    pipeline = Pipeline(
        app_path=app_path,
        poc=poc,
        max_attempts=max_attempts,
        model=model,
        out_dir=out,
        hardcoded_patch=hardcoded_patch,
    )
    pipeline.run()


@app.command()
def verify(
    app_path: Path = typer.Option(..., "--app"),
    poc: Path = typer.Option(..., "--poc"),
    patch_file: Path = typer.Option(..., "--patch"),
) -> None:
    """CI mode: apply a patch, re-run PoC, run regression tests. No LLM."""
    from .pipeline import verify_only

    rc = verify_only(app_path=app_path, poc=poc, patch_file=patch_file)
    raise typer.Exit(code=rc)


@app.command()
def init(
    directory: Path = typer.Argument(Path(".")),
) -> None:
    """Scaffold a patchproof.toml in the target directory."""
    from .init_cmd import scaffold

    scaffold(directory)


if __name__ == "__main__":
    app()
