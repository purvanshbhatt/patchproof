"""Rich TUI for the patching loop."""
from enum import Enum
from rich.console import Console
from rich.panel import Panel
from rich.live import Live
from rich.table import Table

class Verdict(Enum):
    RED = "🔴 VULNERABLE"
    GREEN = "🟢 PATCHED"
    REGRESSION = "🟡 BROKEN"
    STILL_RED = "🔴 FAILED TO PATCH"
    NOT_EXPLOITABLE = "⚪ NOT EXPLOITABLE"

class LiveDisplay:
    def __init__(self, console: Console):
        self.console = console

    def banner(self, run_id: str, app: str, poc: str) -> None:
        self.console.print(Panel(f"[bold cyan]PatchProof[/bold cyan] Run: [yellow]{run_id}[/yellow]\nApp: {app}\nPoC: {poc}"))

    def stage(self, stage: str) -> None:
        self.console.print(f"[bold blue]→ Stage:[/bold blue] [white]{stage}[/white]")

    def info(self, msg: str) -> None:
        self.console.print(f"  [dim]info:[/dim] {msg}")

    def warn(self, msg: str) -> None:
        self.console.print(f"  [yellow]warn:[/yellow] {msg}")

    def attempt(self, current: int, total: int) -> None:
        self.console.print(f"  [bold]Attempt {current}/{total}...[/bold]")

    def verdict(self, v: Verdict) -> None:
        self.console.print(Panel(f"[bold]{v.value}[/bold]", style="bold white on blue" if v == Verdict.GREEN else ""))
