# PatchProof

> **Deterministic exploit repro + AI patch verification engine.**
> Bridging the gap between "we found a bug" and "we proved the fix works."

PatchProof takes a target source tree and a Proof-of-Concept exploit (curl,
raw HTTP, Nuclei template, Python script), spins up an **ephemeral Docker
sandbox**, confirms the exploit reproduces (🔴 **Red**), iteratively asks an
LLM to draft a fix, hot-reloads the app, re-runs the exact same PoC, and
emits a **verified `.patch` + regression test + signed attestation** when
the exploit is blocked (🟢 **Green**) without breaking the rest of the test
suite.

```
   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
   │  Ingest PoC │ →  │   Sandbox   │ →  │  Red state  │
   └─────────────┘    └─────────────┘    └──────┬──────┘
                                               ▼
                                       ┌───────────────┐
                                       │  AI patch loop│
                                       │  (≤N attempts)│
                                       └──────┬────────┘
                                              ▼
                              ┌──────────────────────────────┐
                              ▼                              ▼
                       ┌─────────────┐                ┌─────────────┐
                       │ Still red?  │                │   Green ✔   │
                       │  refine…    │                │ regression? │
                       └─────────────┘                └──────┬──────┘
                                                            ▼
                                            ┌───────────────────────────┐
                                            │ fix.patch + regression    │
                                            │ test + signed attestation  │
                                            └───────────────────────────┘
```

---

## Install

```bash
git clone https://github.com/<you>/patchproof
cd patchproof
uv pip install -e '.[all]'          # or: pip install -e '.[all]'
```

Requires a running Docker daemon.

## CLI

```bash
patchproof --help
patchproof run   --app ./tests/fixtures/vuln-fastapi-sqli/app \
                --poc ./tests/fixtures/vuln-fastapi-sqli/poc.txt
patchproof run   --app ./my-app --poc ./sqli.curl --max-attempts 5 --model gpt-4o-mini
patchproof verify --app ./my-app --poc ./sqli.curl --patch ./fix.patch
patchproof init   # scaffold ./patchproof.toml
```

Run artifacts land in `patchproof-out/<run-id>/`:

```
fix.patch                     ← drop-in git diff
attestation.json              ← signed evidence (target SHA + PoC SHA + verdict)
evidence/red.json             ← red baseline response
evidence/attempt_<n>.json     ← every retry
test_security_patchproof.py   ← regression test, ready for CI
```

## Use as a library

```python
from pathlib import Path
from patchproof.pipeline import Pipeline

Pipeline(
    app_path=Path("./my-app"),
    poc=Path("./sqli.curl"),
    max_attempts=5,
    model="gpt-4o-mini",
).run()
```

## MCP server (Cursor / Claude Code)

```jsonc
{
  "mcpServers": {
    "patchproof": {
      "command": "python",
      "args": ["-m", "patchproof.mcp.server"],
      "cwd": "<path to patchproof checkout>"
    }
  }
}
```

Tools exposed:

- `patchproof_run(app_path, poc_path, hardcoded_patch?, max_attempts?, model?)`
- `patchproof_verify(app_path, poc_path, patch_path)`

## CI / pre-commit

- **GitHub Actions**: see `examples/github/patchproof.yml`.
- **pre-commit hook**: see `examples/hooks/pre-commit` (symlink into `.git/hooks/`).

## Architecture

| module                       | role                                                     |
|------------------------------|----------------------------------------------------------|
| `ingest.normalize`           | curl / raw HTTP / Nuclei / Python → normalized `PoC`     |
| `sandbox.app_spec`           | Detect runtime + framework, pick base image & reload cmd |
| `sandbox.docker`             | Ephemeral container, hot-reload, exec PoC, run tests     |
| `patch.locator`              | tree-sitter / regex → most likely vulnerable `file:line` |
| `patch.llm`                  | LiteLLM → unified diff                                   |
| `patch.apply`                | `git apply` (or hand-rolled) + snapshot rollback         |
| `regression.runner`          | `docker exec` the framework test suite                   |
| `report.attestation`         | JSON evidence + optional ed25519 signature               |
| `report.tui`                 | Rich live display                                        |

## Development

```bash
uv pip install -e '.[dev]'
pytest -m 'not integration'          # unit tests (no Docker)
pytest                                # all tests (needs Docker)
ruff check src tests
```

## License

Apache-2.0.
