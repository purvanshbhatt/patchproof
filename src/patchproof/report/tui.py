"""Rich TUI for the patching loop."""
from __future__ import annotations

from enum import Enum

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.syntax import Syntax
from rich.table import Table


class Verdict(Enum):
    RED = ("RED", "bold white on red")
    GREEN = ("GREEN", "bold white on green")
    REGRESSION = ("REGRESSION", "bold white on yellow")
    STILL_RED = ("STILL RED", "bold white on red")
    NOT_EXPLOITABLE = ("NOT EXPLOITABLE", "bold white on grey50")


class LiveDisplay:
    def __init__(self, console: Console):
        self.console = console

    def banner(self, run_id: str, app: str, poc: str) -> None:
        table = Table.grid(padding=(0, 1))
        table.add_row("[bold cyan]PatchProof[/bold cyan] v0.1.0")
        table.add_row(f"[yellow]Run:[/yellow] {run_id}")
        table.add_row(f"[yellow]App:[/yellow] {app}")
        table.add_row(f"[yellow]PoC:[/yellow] {poc}")
        self.console.print(Panel(table, border_style="cyan"))

    def stage(self, stage: str) -> None:
        self.console.rule(f"[bold blue]Stage: {stage}[/bold blue]")

    def info(self, msg: str) -> None:
        self.console.print(f"  [dim]info:[/dim] {msg}")

    def warn(self, msg: str) -> None:
        self.console.print(f"  [yellow]warn:[/yellow] {msg}")

    def error(self, msg: str) -> None:
        self.console.print(f"  [red]error:[/red] {msg}")

    def attempt(self, current: int, total: int) -> None:
        self.console.print(f"  [bold]Attempt {current}/{total}[/bold]")

    def diff(self, text: str, title: str = "patch") -> None:
        self.console.print(
            Panel(Syntax(text, "diff", theme="monokai", word_wrap=True), title=title, border_style="magenta")
        )

    def response(self, status: int, body: str, title: str = "PoC response") -> None:
        body = body[:1500] + ("\n... [truncated]" if len(body) > 1500 else "")
        self.console.print(
            Panel(
                f"[bold]HTTP {status}[/bold]\n\n{body}",
                title=title,
                border_style="red" if status >= 500 else "blue",
            )
        )

    def verdict(self, v: Verdict) -> None:
        label, style = v.value
        self.console.print(Panel(f"[bold]{label}[/bold]", style=style))

    def progress(self) -> Progress:
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
        )
