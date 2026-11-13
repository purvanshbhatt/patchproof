from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from . import __version__

app = typer.Typer(
    name="patchproof",
    help="Exploit-verified patch engine: reproduce, patch, re-exploit, attest.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()

RunnerOpt = typer.Option("auto", "--runner", help="Sandbox backend: auto|local|docker.")


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"patchproof {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None, "--version", callback=_version_callback, is_eager=True,
        help="Show version and exit."),
) -> None:
    """PatchProof CLI."""


@app.command()
def run(
    app_path: Path = typer.Option(..., "--app", help="Path to target app source."),
    poc: Path = typer.Option(..., "--poc", help="PoC file (curl | raw HTTP | nuclei | python)."),
    max_attempts: int = typer.Option(5, "--max-attempts", help="Max LLM patch iterations."),
    model: str = typer.Option("anthropic/claude-sonnet-4-5", "--model", help="LiteLLM model id."),
    out: Path = typer.Option(Path("patchproof-out"), "--out", help="Output directory."),
    runner: str = RunnerOpt,
    no_variants: bool = typer.Option(False, "--no-variants", help="Skip variant-PoC replay."),
    emit_vex: bool = typer.Option(False, "--emit-vex", help="Also write an OpenVEX document."),
    vuln_id: str = typer.Option("PATCHPROOF-UNSPECIFIED", "--vuln-id", help="CVE/ID for VEX."),
    hardcoded_patch: Path | None = typer.Option(
        None, "--hardcoded-patch", help="Apply this diff instead of calling the LLM."),
) -> None:
    """Run the full red -> patch -> green -> regression -> attest loop."""
    from .pipeline import Pipeline

    rc = Pipeline(
        app_path=app_path, poc=poc, max_attempts=max_attempts, model=model, out_dir=out,
        hardcoded_patch=hardcoded_patch, runner_backend=runner,
        check_variants=not no_variants, vuln_id=vuln_id, emit_vex=emit_vex,
    ).run()
    raise typer.Exit(code=rc)


@app.command()
def verify(
    app_path: Path = typer.Option(..., "--app"),
    poc: Path = typer.Option(..., "--poc"),
    patch_file: Path = typer.Option(..., "--patch"),
    runner: str = RunnerOpt,
    no_variants: bool = typer.Option(False, "--no-variants"),
) -> None:
    """CI mode: apply a patch, re-run the exploit + variants, run tests. No LLM.

    Exit 0 only if the exploit (and its variants) is blocked and tests pass."""
    from .pipeline import verify_only

    rc = verify_only(app_path=app_path, poc=poc, patch_file=patch_file,
                     runner_backend=runner, check_variants=not no_variants)
    raise typer.Exit(code=rc)


@app.command()
def init(directory: Path = typer.Argument(Path("."))) -> None:
    """Scaffold a patchproof.toml in the target directory."""
    from .init_cmd import scaffold

    scaffold(directory)


if __name__ == "__main__":
    app()
