# PatchProof

**Exploit-verified patching for web apps.** PatchProof reproduces an exploit
against your app in a sandbox (red), applies a patch (yours or an LLM's),
re-runs the exploit to prove it is blocked (green), replays mutated variants of
the exploit, runs your regression tests, and emits a signed attestation plus a
ready-to-run regression test.

The verdict is not "the scanner stopped complaining." It is **"the exploit no
longer works, its variants no longer work, and your tests still pass"** —
checked by execution, not by static analysis.

```
red  ──▶  patch  ──▶  green  ──▶  variants  ──▶  regression  ──▶  attest
exploit   apply       re-run      mutated        your tests      in-toto
fires     diff        blocked?    PoCs blocked?   still pass?     statement
```

## Why it exists

Commercial AI auto-fix tools (Copilot Autofix, Snyk Agent Fix, Semgrep, Pixee,
Veracode, Checkmarx) verify a fix by **re-running the static scanner** that
raised the finding. That answers "does the pattern still match?", not "is the
app still exploitable?". The research-grade definition of a verified
patch — used by the DARPA AIxCC 2025 finalists and benchmarks like CyberGym,
PatchEval, and Vul4J — is execution-based: a proof-of-vulnerability that worked
before no longer works, *and* functional tests still pass.

That execution-based bar exists for fuzzer crashes in C/C++ libraries. It does
**not** exist as an easy-to-run, open tool for **deployed web apps with
HTTP-level PoCs**. PatchProof fills that gap, and adds two things the research
consensus says you need:

- **Variant replay.** AIxCC required patches to block *all variant* PoVs,
  because a patch that only blocks the exact payload (a WAF-style string check)
  is over-fitted. PatchProof auto-mutates the PoC (case flips, URL-encoding,
  comment splicing) and fails the patch if any variant still succeeds.
- **Honest labels.** A fraction of patches that pass exploit-replay and tests
  are still semantically wrong. PatchProof records `semantic_review: none` and
  says so in the attestation, instead of claiming "fixed."

See [docs/POSITIONING.md](docs/POSITIONING.md) for the full landscape.

## Install

```bash
pip install -e .            # or: uv pip install -e .
```

The `local` runner needs only Python. The `docker` runner needs a running
Docker daemon.

## Quickstart

```bash
patchproof run \
  --app ./tests/fixtures/vuln-fastapi-sqli/app \
  --poc ./tests/fixtures/vuln-fastapi-sqli/poc.txt \
  --hardcoded-patch ./tests/fixtures/vuln-fastapi-sqli/fix.patch \
  --runner local
```

Drop `--hardcoded-patch` to have an LLM generate the patch (needs
[LiteLLM](https://docs.litellm.ai/) credentials, e.g. `ANTHROPIC_API_KEY`):

```bash
patchproof run --app ./app --poc ./poc.txt --model anthropic/claude-sonnet-4-5
```

## PoC formats

PatchProof auto-detects and normalizes:

- **curl** one-liners: `curl "http://host/?id=' OR '1'='1'"`
- **raw HTTP** requests: `GET /admin?debug=1 HTTP/1.1` …
- **Nuclei** templates (first request + matcher)
- **Python** scripts (run inside the sandbox; print `EXPLOIT_OK` / `EXPLOIT_FAIL`)

A leading directive line overrides the success oracle:

```
#patchproof: marker=EXPLOIT_LEAK status=500
```

## Verdicts

| Verdict | Exit | Meaning |
|---------|------|---------|
| EXPLOIT-VERIFIED PATCH | 0 | exploit + variants blocked, tests pass |
| NOT EXPLOITABLE | 0 | PoC did not reproduce; nothing to patch |
| FAILED TO PATCH | 2 | exploit still succeeds after every attempt |
| PATCH BROKE TESTS | 3 | exploit blocked but regression tests fail |
| PATCH DID NOT APPLY | 4 | diff could not be applied |
| WEAK PATCH | 5 | base blocked, but a variant still succeeds (over-fitted) |

## CI gate

`verify` applies a committed patch, re-runs the exploit and its variants, and
runs your tests. No LLM. Exit code 0 only if the exploit is truly blocked — wire
it as a required check:

```yaml
- run: pip install patchproof
- run: |
    patchproof verify \
      --app ./app --poc ./security/poc.txt --patch ./security/fix.patch \
      --runner local
```

A fuller example is in [docs/example-github-action.yml](docs/example-github-action.yml).

## Output artifacts

Each run writes to `patchproof-out/<run-id>/`:

- `fix.patch` — the effective patch (diff vs baseline)
- `attestation.json` — an [in-toto](https://in-toto.io/) Statement with a
  `patchproof/exploit-verified/v0.1` predicate: PoC digest, pre/post outcomes,
  variant results, regression result, and an explicit disclaimer
- `artifacts/test_patchproof_regression.py` — a pytest that replays the exploit
- `artifacts/patchproof-regression.yaml` — a Nuclei template for the same
- `evidence/` — raw red/green/attempt records

Add `--emit-vex --vuln-id CVE-XXXX-NNNN` to also write an OpenVEX `fixed`
statement.

## Security

PatchProof runs untrusted PoCs and vulnerable apps. The PoC is treated as data,
the LLM never sees it raw, and the Docker runner uses `--network none`, no
published port, dropped capabilities, and no Docker socket. See
[SECURITY.md](SECURITY.md) for the full threat model and the limits of a green
verdict.

## Architecture

```
patchproof/
  ingest/normalize.py   PoC parsing, success oracle, variant generation
  sandbox/app_spec.py   runtime/framework/entrypoint detection
  sandbox/runner.py     LocalRunner + DockerRunner (serve, replay, test)
  patch/apply.py        git-backed apply / rollback on a working copy
  patch/locator.py      rank likely-vulnerable files for the generator
  patch/llm.py          injection-safe LLM patch generation (LiteLLM)
  report/attestation.py in-toto predicate + OpenVEX
  report/tui.py         Rich progress output
  pipeline.py           the red -> green -> attest orchestration
```

## Development

```bash
pip install -e '.[dev]'
ruff check src tests
pytest
```

## License

Apache-2.0. See [LICENSE](LICENSE).
