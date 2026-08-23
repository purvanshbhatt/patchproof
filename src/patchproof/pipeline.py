"""Top-level orchestration: ingest → sandbox → red → patch → green → attest."""
from __future__ import annotations

import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console

from .ingest.normalize import load_poc
from .patch.apply import Snapshot, snapshot
from .report.attestation import Attestation, write_attestation
from .report.tui import LiveDisplay, Verdict
from .sandbox.app_spec import detect_app_spec
from .sandbox.docker import Sandbox

console = Console()


@dataclass
class PipelineResult:
    red: bool = False
    green: bool = False
    attempts: int = 0
    patch_path: Path | None = None
    attestation_path: Path | None = None
    artifacts: list[Path] = field(default_factory=list)


@dataclass
class Pipeline:
    app_path: Path
    poc: Path
    max_attempts: int = 5
    model: str = "gpt-4o-mini"
    out_dir: Path = Path("patchproof-out")
    hardcoded_patch: Path | None = None

    def run(self) -> PipelineResult:
        run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
        out_dir = self.out_dir / run_id
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "evidence").mkdir(exist_ok=True)

        result = PipelineResult()

        display = LiveDisplay(console=console)
        display.banner(run_id, str(self.app_path), str(self.poc))

        # --- Snapshot BEFORE any source mutation ---
        snap: Snapshot | None = snapshot(self.app_path) if not _is_git_repo(self.app_path) else None

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

        try:
            # --- Red baseline ---
            display.stage("red")
            red = sandbox.run_poc(poc_obj)
            (out_dir / "evidence" / "red.json").write_text(red.as_json())
            if not red.exploit_succeeded:
                display.verdict(Verdict.NOT_EXPLOITABLE)
                result.attestation_path = out_dir / "attestation.json"
                write_attestation(
                    Attestation(
                        target_sha=sandbox.target_sha(),
                        poc_sha=poc_obj.sha256(),
                        attempts=0,
                        model=self.model,
                        verdict="not_exploitable",
                    ),
                    result.attestation_path,
                )
                result.artifacts.append(result.attestation_path)
                return result
            result.red = True
            display.verdict(Verdict.RED)

            # --- Patch loop ---
            display.stage("patch-loop")
            if self.hardcoded_patch is not None:
                patch_text = self.hardcoded_patch.read_text()
                display.info("Using hardcoded patch (skeleton mode, LLM skipped)")
                attempts = 1
            else:
                from .patch.apply import apply_diff, rollback
                from .patch.llm import generate_patch
                from .patch.locator import locate

                attempts = 0
                patch_text = ""
                green = False
                last_response = red.raw_response
                for i in range(1, self.max_attempts + 1):
                    attempts = i
                    display.attempt(i, self.max_attempts)
                    target = locate(red, self.app_path)
                    display.info(f"target → {target}")
                    patch_text = generate_patch(
                        target=target,
                        poc=poc_obj,
                        red_response=last_response,
                        model=self.model,
                    )
                    if not patch_text:
                        display.warn("LLM returned empty diff; retrying")
                        continue
                    if not apply_diff(self.app_path, patch_text):
                        display.warn("diff did not apply; retrying")
                        rollback(self.app_path, snap)
                        continue
                    sandbox.reload()
                    rep = sandbox.run_poc(poc_obj)
                    (out_dir / "evidence" / f"attempt_{i}.json").write_text(rep.as_json())
                    if not rep.exploit_succeeded:
                        green = True
                        break
                    display.warn("exploit still succeeds; refining patch")
                    rollback(self.app_path, snap)
                    last_response = rep.raw_response
                result.attempts = attempts
                if not green:
                    display.verdict(Verdict.STILL_RED)
                    rollback(self.app_path, snap)
                    result.attestation_path = out_dir / "attestation.json"
                    write_attestation(
                        Attestation(
                            target_sha=sandbox.target_sha(),
                            poc_sha=poc_obj.sha256(),
                            attempts=attempts,
                            model=self.model,
                            verdict="still_red",
                        ),
                        result.attestation_path,
                    )
                    result.artifacts.append(result.attestation_path)
                    return result

            # --- Regression ---
            display.stage("regression")
            if not sandbox.run_tests():
                display.verdict(Verdict.REGRESSION)
                rollback(self.app_path, snap)
                result.attestation_path = out_dir / "attestation.json"
                write_attestation(
                    Attestation(
                        target_sha=sandbox.target_sha(),
                        poc_sha=poc_obj.sha256(),
                        attempts=attempts,
                        model=self.model if self.hardcoded_patch is None else "hardcoded",
                        verdict="regression",
                    ),
                    result.attestation_path,
                )
                result.artifacts.append(result.attestation_path)
                return result

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
            console.print(f"[bold green]Done.[/bold green] Artifacts in [cyan]{out_dir}[/cyan]")
            return result
        finally:
            sandbox.down()
            # NOTE: we intentionally leave the patched source in place if we
            # returned green; otherwise we rolled back during the loop.


def _is_git_repo(path: Path) -> bool:
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=path,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return r.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def verify_only(*, app_path: Path, poc: Path, patch_file: Path) -> int:
    """CI mode. Returns 0 on green, non-zero on red or regression."""
    from .patch.apply import apply_diff, rollback
    from .patch.apply import snapshot as _snapshot

    spec = detect_app_spec(app_path)
    out_dir = Path("patchproof-out") / "verify"
    out_dir.mkdir(parents=True, exist_ok=True)

    sandbox = Sandbox(app_path=app_path, spec=spec, out_dir=out_dir)
    sandbox.up()
    snap = _snapshot(app_path) if not _is_git_repo(app_path) else None
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
        rep = sandbox.run_poc(poc_obj)
        if rep.exploit_succeeded:
            rollback(app_path, snap)
            console.print("[red]Patch failed to block exploit.[/red]")
            return 5
        if not sandbox.run_tests():
            rollback(app_path, snap)
            console.print("[red]Patch broke regression tests.[/red]")
            return 6
        console.print("[bold green]Verified.[/bold green]")
        return 0
    finally:
        sandbox.down()
