"""Top-level orchestration: ingest -> sandbox -> red -> patch -> green -> attest.

Exit codes (also the return value of run()/verify_only()):
  0  green (exploit-verified patch) OR not exploitable
  2  still red (exploit survives every attempt)
  3  patch broke regression tests
  4  patch did not apply
  5  weak patch (base blocked but a variant still succeeds)
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console

from . import __version__
from .ingest.normalize import PoC, load_poc
from .patch.apply import WorkCopy, apply_diff, diff_against_baseline, rollback
from .report.attestation import (
    Attestation,
    ExploitVerifiedPredicate,
    VariantOutcome,
    now_iso,
    tree_sha256,
    write_attestation,
    write_openvex,
)
from .report.tui import LiveDisplay, Verdict
from .sandbox.app_spec import detect_app_spec
from .sandbox.runner import make_runner

console = Console()

OK, STILL_RED, REGRESSION, NO_APPLY, WEAK = 0, 2, 3, 4, 5


@dataclass
class Pipeline:
    app_path: Path
    poc: Path
    max_attempts: int = 5
    model: str = "anthropic/claude-sonnet-4-5"
    out_dir: Path = Path("patchproof-out")
    hardcoded_patch: Path | None = None
    runner_backend: str = "auto"
    check_variants: bool = True
    vuln_id: str = "PATCHPROOF-UNSPECIFIED"
    emit_vex: bool = False

    def run(self) -> int:
        run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
        out_dir = Path(self.out_dir) / run_id
        (out_dir / "evidence").mkdir(parents=True, exist_ok=True)
        (out_dir / "artifacts").mkdir(parents=True, exist_ok=True)

        d = LiveDisplay(console)
        d.banner(run_id, str(self.app_path), str(self.poc), self.runner_backend)

        d.stage("ingest")
        poc = load_poc(Path(self.poc))
        from rich.markup import escape
        d.info(escape(f"poc kind: {poc.kind}  oracle markers: {list(poc.oracle.markers)[:3]}"))

        d.stage("workcopy")
        workdir = WorkCopy(src=Path(self.app_path), dest=out_dir / "workcopy").setup()
        spec = detect_app_spec(workdir)
        d.info(f"detected {spec.runtime}/{spec.framework} entry={spec.entry_file} app={spec.app_var}")

        d.stage("sandbox")
        runner = make_runner(self.runner_backend, workdir, spec)
        runner.up()
        d.info(f"serving at {runner.base_url}")

        try:
            # --- RED baseline ---
            d.stage("red")
            red = runner.run_poc(poc)
            (out_dir / "evidence" / "red.json").write_text(red.as_json())
            if not red.succeeded:
                d.info(f"status={red.status} {red.note}")
                d.verdict(Verdict.NOT_EXPLOITABLE)
                return OK
            d.verdict(Verdict.RED)

            # --- Patch loop ---
            d.stage("patch")
            attempts, applied = self._obtain_patch(d, runner, poc, red, workdir, out_dir)
            if not applied:
                d.verdict(Verdict.STILL_RED)
                return STILL_RED

            # --- GREEN: base exploit must be blocked ---
            green = runner.run_poc(poc)
            (out_dir / "evidence" / "green.json").write_text(green.as_json())
            if green.succeeded:
                rollback(workdir)
                d.verdict(Verdict.STILL_RED)
                return STILL_RED

            # --- Variant replay (over-fitting / WAF-string guard) ---
            variant_results: list[VariantOutcome] = []
            if self.check_variants:
                d.stage("variants")
                for v in poc.variants():
                    res = runner.run_poc(v)
                    variant_results.append(VariantOutcome(v.label, blocked=not res.succeeded))
                if variant_results:
                    d.variant_table([(v.label, v.blocked) for v in variant_results])
                if any(not v.blocked for v in variant_results):
                    d.verdict(Verdict.VARIANTS_FAILED)
                    self._attest(out_dir, workdir, poc, red, attempts, variant_results,
                                 reg_ok=False, reg_note="not run (weak patch)", runner_name=type(runner).__name__)
                    return WEAK

            # --- Regression ---
            d.stage("regression")
            reg_ok, reg_note = runner.run_tests()
            d.info(reg_note.splitlines()[-1] if reg_note else "")
            if not reg_ok:
                rollback(workdir)
                d.verdict(Verdict.REGRESSION)
                self._attest(out_dir, workdir, poc, red, attempts, variant_results,
                             reg_ok=False, reg_note=reg_note, runner_name=type(runner).__name__)
                return REGRESSION

            # --- Artifacts + attestation ---
            d.stage("attest")
            self._write_fix(out_dir, workdir)
            self._emit_regression_artifacts(out_dir, poc)
            self._attest(out_dir, workdir, poc, red, attempts, variant_results,
                         reg_ok=True, reg_note=reg_note, runner_name=type(runner).__name__)
            d.verdict(Verdict.GREEN)
            console.print(f"[bold green]Done.[/bold green] artifacts in [cyan]{out_dir}[/cyan]")
            return OK
        finally:
            runner.down()

    # ------------------------------------------------------------------ #
    def _obtain_patch(self, d, runner, poc, red, workdir, out_dir) -> tuple[int, bool]:
        if self.hardcoded_patch is not None:
            text = Path(self.hardcoded_patch).read_text()
            d.info("applying supplied patch (no LLM)")
            if not apply_diff(workdir, text):
                d.warn("patch did not apply")
                return 1, False
            runner.reload()
            return 1, True

        from .patch.llm import generate_patch
        from .patch.locator import locate

        for i in range(1, self.max_attempts + 1):
            d.attempt(i, self.max_attempts)
            targets = locate(red, workdir)
            diff = generate_patch(targets=targets, poc=poc, red=red, model=self.model)
            (out_dir / "evidence" / f"attempt_{i}.diff").write_text(diff or "")
            if not diff.strip():
                d.warn("model returned no diff")
                continue
            if not apply_diff(workdir, diff):
                d.warn("diff did not apply; retrying")
                continue
            runner.reload()
            rep = runner.run_poc(poc)
            if not rep.succeeded:
                return i, True
            d.warn("exploit still succeeds; rolling back")
            rollback(workdir)
            runner.reload()
        return self.max_attempts, False

    def _write_fix(self, out_dir, workdir) -> None:
        (out_dir / "fix.patch").write_text(diff_against_baseline(workdir))

    def _emit_regression_artifacts(self, out_dir, poc: PoC) -> None:
        req = poc.payload
        art = out_dir / "artifacts"
        # pytest replay (dev team re-runs it)
        markers = list(poc.oracle.markers)[:3]
        (art / "test_patchproof_regression.py").write_text(
            "import os, httpx\n"
            "BASE = os.environ['PATCHPROOF_BASE_URL']\n"
            f"PATH = {req.get('url', '/')!r}\n"
            f"METHOD = {req.get('method', 'GET')!r}\n"
            f"MARKERS = {markers!r}\n"
            "def test_exploit_blocked():\n"
            "    r = httpx.request(METHOD, BASE.rstrip('/') + '/' + PATH.lstrip('/'), timeout=10)\n"
            "    assert r.status_code < 500, 'app crashed'\n"
            "    low = r.text.lower()\n"
            "    for m in MARKERS:\n"
            "        assert m.lower() not in low, f'leak marker still present: {m}'\n"
        )
        # Nuclei template (security team re-runs it in CI)
        (art / "patchproof-regression.yaml").write_text(
            "id: patchproof-regression\n"
            "info:\n  name: PatchProof regression\n  severity: info\n"
            "http:\n"
            f"  - method: {req.get('method', 'GET')}\n"
            "    path:\n"
            f"      - \"{{{{BaseURL}}}}{req.get('url', '/')}\"\n"
            "    matchers-condition: or\n"
            "    matchers:\n"
            "      - type: status\n        status:\n          - 500\n"
            + ("      - type: word\n        words:\n"
               + "".join(f"          - \"{m}\"\n" for m in markers) if markers else "")
        )

    def _attest(self, out_dir, workdir, poc, red, attempts, variant_results, *,
                reg_ok, reg_note, runner_name) -> None:
        pred = ExploitVerifiedPredicate(
            tool="patchproof", tool_version=__version__, timestamp=now_iso(),
            poc_sha256=poc.sha256(), poc_kind=poc.kind,
            pre_patch_exploit_succeeded=True,
            post_patch_exploit_blocked=True,
            variants_total=len(variant_results),
            variants_blocked=sum(1 for v in variant_results if v.blocked),
            variant_results=variant_results,
            regression_passed=reg_ok,
            regression_note=(reg_note or "")[:500],
            runner=runner_name,
            model=self.model if self.hardcoded_patch is None else "supplied-patch",
            attempts=attempts,
        )
        att = Attestation(
            subject_name=str(self.app_path),
            subject_sha256=tree_sha256(workdir),
            predicate=pred,
        )
        write_attestation(att, out_dir / "attestation.json")
        if self.emit_vex and reg_ok:
            write_openvex(path=out_dir / "openvex.json", vuln_id=self.vuln_id,
                          product=str(self.app_path))


def verify_only(*, app_path: Path, poc: Path, patch_file: Path,
                runner_backend: str = "auto", check_variants: bool = True) -> int:
    """CI mode: reproduce exploit, apply supplied patch, require exploit (and
    variants) blocked and tests still passing. No LLM."""
    out = Path("patchproof-out") / "verify"
    (out).mkdir(parents=True, exist_ok=True)
    poc_obj = load_poc(Path(poc))
    workdir = WorkCopy(src=Path(app_path), dest=out / "workcopy").setup()
    spec = detect_app_spec(workdir)
    runner = make_runner(runner_backend, workdir, spec)
    runner.up()
    try:
        red = runner.run_poc(poc_obj)
        if not red.succeeded:
            console.print("[yellow]PoC did not reproduce; nothing to verify.[/yellow]")
            return OK
        if not apply_diff(workdir, Path(patch_file).read_text()):
            console.print("[red]Patch did not apply.[/red]")
            return NO_APPLY
        runner.reload()
        if runner.run_poc(poc_obj).succeeded:
            console.print("[red]Patch failed to block the exploit.[/red]")
            return STILL_RED
        if check_variants:
            for v in poc_obj.variants():
                if runner.run_poc(v).succeeded:
                    console.print(f"[red]Variant '{v.label}' still succeeds.[/red]")
                    return WEAK
        ok, note = runner.run_tests()
        if not ok:
            console.print(f"[red]Patch broke tests:[/red]\n{note}")
            return REGRESSION
        console.print("[bold green]Verified: exploit blocked, variants blocked, tests pass.[/bold green]")
        return OK
    finally:
        runner.down()
