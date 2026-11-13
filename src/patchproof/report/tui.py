"""Rich TUI for the red -> green loop."""
from __future__ import annotations

from enum import Enum

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


class Verdict(Enum):
    RED = "VULNERABLE (exploit reproduced)"
    GREEN = "EXPLOIT-VERIFIED PATCH (exploit + variants blocked, tests pass)"
    STILL_RED = "FAILED TO PATCH (exploit still succeeds)"
    VARIANTS_FAILED = "WEAK PATCH (base blocked, a variant still succeeds)"
    REGRESSION = "PATCH BROKE TESTS"
    NOT_EXPLOITABLE = "NOT EXPLOITABLE (PoC did not reproduce)"


_STYLE = {
    Verdict.GREEN: "bold white on green",
    Verdict.RED: "bold white on red",
    Verdict.STILL_RED: "bold white on red",
    Verdict.VARIANTS_FAILED: "bold black on yellow",
    Verdict.REGRESSION: "bold black on yellow",
    Verdict.NOT_EXPLOITABLE: "bold white on blue",
}


class LiveDisplay:
    def __init__(self, console: Console):
        self.console = console

    def banner(self, run_id: str, app: str, poc: str, runner: str) -> None:
        self.console.print(Panel(
            f"[bold cyan]PatchProof[/bold cyan]  run [yellow]{run_id}[/yellow]\n"
            f"app:    {app}\npoc:    {poc}\nrunner: {runner}",
            title="exploit-verified patching", border_style="cyan",
        ))

    def stage(self, stage: str) -> None:
        self.console.print(f"[bold blue]->[/bold blue] [white]{stage}[/white]")

    def info(self, msg: str) -> None:
        self.console.print(f"   [dim]{msg}[/dim]")

    def warn(self, msg: str) -> None:
        self.console.print(f"   [yellow]warn:[/yellow] {msg}")

    def attempt(self, current: int, total: int) -> None:
        self.console.print(f"   [bold]patch attempt {current}/{total}[/bold]")

    def variant_table(self, rows: list[tuple[str, bool]]) -> None:
        t = Table(title="variant PoCs", show_header=True, header_style="bold")
        t.add_column("variant")
        t.add_column("blocked")
        for label, blocked in rows:
            t.add_row(label, "[green]yes[/green]" if blocked else "[red]NO[/red]")
        self.console.print(t)

    def verdict(self, v: Verdict) -> None:
        self.console.print(Panel(f"[bold]{v.value}[/bold]", style=_STYLE.get(v, "")))
