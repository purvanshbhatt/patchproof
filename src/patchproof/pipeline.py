"""Top-level orchestration: ingest → sandbox → red → patch → green → attest."""
from __future__ import annotations

import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from rich.console import Console

from .ingest.normalize import load_poc, PoC
from .report.attestation import Attestation, write_attestation
from .report.tui import LiveDisplay, Verdict
from .sandbox.docker import Sandbox
from .sandbox.app_spec import detect_app_spec, AppSpec

console = Console()


@dataclass
class PipelineResult:
    red: bool = False
    green: bool = False
    attempts: int = 0
    patch_path: Optional[Path] = None
    attestation_path: Optional[Path] = None
    artifacts: list[Path] = field(default_factory=list)


@dataclass
class Pipeline:
    app_path: Path
    poc: Path
    max_attempts: int = 5
    model: str = "gpt-4o-mini"
    out_dir: Path = Path("patchproof-out")
    hardcoded_patch: Optional[Path] = None

    def run(self) -> PipelineResult:
        run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
        out_dir = self.out_dir / run_id
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "evidence").mkdir(exist_ok=True)

        result = PipelineResult()

        display = LiveDisplay(console=console)
        display.banner(run_id, str(self.app_path), str(self.poc))

        # --- Ingest ---
        display.stage("ingest")
        poc_obj = load_poc(self.poc)
        display.info(f"PoC kind: {poc_obj.kind}")

        # --- Sandbox ---
        display.stage("sandbox")
        spec = detect_app_spec(self.app_path)
        sandbox = Sandbox(app_path=self.app_path, spec=spec, out_dir=out_dir)
        sandbox.up()
        display.info(f"Container up: {sandbox.url}")

        # --- Red baseline ---
        display.stage("red")
        red = sandbox.run_poc(poc_obj)
        (out_dir / "evidence" / "red.json").write_text(red.as_json())
        if not red.exploit_succeeded:
            display.verdict(Verdict.NOT_EXPLOITABLE)
            sandbox.down()
            raise SystemExit(0)
        result.red = True
        display.verdict(Verdict.RED)

        # --- Patch loop ---
        display.stage("patch-loop")
        if self.hardcoded_patch is not None:
            patch_text = self.hardcoded_patch.read_text()
            display.info("Using hardcoded patch (skeleton mode, LLM skipped)")
            attempts = 1
        else:
            from .patch.llm import generate_patch
            from .patch.locator import locate
            from .patch.apply import apply_diff, rollback

            attempts = 0
            patch_text = ""
            green = False
            last_response = red.raw_response
            for i in range(1, self.max_attempts + 1):
                attempts = i
                display.attempt(i, self.max_attempts)
                target = locate(red, self.app_path)
                patch_text = generate_patch(
                    target=target,
                    poc=poc_obj,
                    red_response=red.raw_response,
                    model=self.model,
                )
                ok = apply_diff(self.app_path, patch_text)
                if not ok:
                    display.warn("diff did not apply; retrying")
                    continue
                sandbox.reload()
                time.sleep(0.5)
                rep = sandbox.run_poc(poc_obj)
                (out_dir / "evidence" / f"attempt_{i}.json").write_text(rep.as_json())
                if not rep.exploit_succeeded:
                    green = True
                    break
                rollback(self.app_path)
                last_response = rep.raw_response
            result.attempts = attempts
            if not green:
                display.verdict(Verdict.STILL_RED)
                sandbox.down()
                raise SystemExit(2)

        # Apply the final patch to disk for artifact emission.
        if self.hardcoded_patch is None:
            from .patch.apply import apply_diff as _apply
            _apply(self.app_path, patch_text)

        # --- Regression ---
        display.stage("regression")
        if not sandbox.run_tests():
            display.verdict(Verdict.REGRESSION)
            sandbox.down()
            raise SystemExit(3)

        # --- Artifacts ---
        display.stage("attest")
        fix_path = out_dir / "fix.patch"
        fix_path.write_text(patch_text)
        result.patch_path = fix_path

        regression_test = sandbox.write_regression_test(poc_obj)
        if regression_test is not None:
            result.artifacts.append(regression_test)

        attest = Attestation(
            target_sha=sandbox.target_sha(),
            poc_sha=poc_obj.sha256(),
            attempts=attempts if self.hardcoded_patch is None else 1,
            model=self.model if self.hardcoded_patch is None else "hardcoded",
            verdict="green",
        )
        result.attestation_path = out_dir / "attestation.json"
        write_attestation(attest, result.attestation_path)
        result.artifacts.append(result.attestation_path)

        display.verdict(Verdict.GREEN)
        sandbox.down()
        console.print(f"[bold green]Done.[/bold green] Artifacts in [cyan]{out_dir}[/cyan]")
        return result


def verify_only(*, app_path: Path, poc: Path, patch_file: Path) -> int:
    """CI mode. Returns 0 on green, non-zero on red or regression."""
    from .patch.apply import apply_diff, rollback

    spec = detect_app_spec(app_path)
    out_dir = Path("patchproof-out") / "verify"
    out_dir.mkdir(parents=True, exist_ok=True)

    sandbox = Sandbox(app_path=app_path, spec=spec, out_dir=out_dir)
    sandbox.up()
    try:
        poc_obj = load_poc(poc)
        red = sandbox.run_poc(poc_obj)
        if not red.exploit_succeeded:
            console.print("[yellow]PoC did not reproduce; nothing to verify.[/yellow]")
            return 0
        if not apply_diff(app_path, patch_file.read_text()):
            console.print("[red]Patch did not apply.[/red]")
            return 4
        sandbox.reload()
        import time as _t
        _t.sleep(0.5)
        rep = sandbox.run_poc(poc_obj)
        if rep.exploit_succeeded:
            rollback(app_path)
            console.print("[red]Patch failed to block exploit.[/red]")
            return 5
        if not sandbox.run_tests():
            rollback(app_path)
            console.print("[red]Patch broke regression tests.[/red]")
            return 6
        console.print("[bold green]Verified.[/bold green]")
        return 0
    finally:
        sandbox.down()
