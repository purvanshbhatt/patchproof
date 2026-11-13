# Contributing

## Setup

```bash
pip install -e '.[dev]'   # or: uv pip install -e '.[dev]'
```

## Checks (run before pushing)

```bash
ruff check src tests
pytest
```

Integration tests build per-fixture virtualenvs and are skipped automatically
when there is no network to install dependencies.

## Adding a vulnerability fixture

A fixture is a self-contained vulnerable app plus a PoC and a known-good patch,
used by both the test suite and the CI self-verify job.

```
tests/fixtures/<name>/
  app/              a runnable vulnerable web app (FastAPI, Flask, Express, ...)
    requirements.txt (or package.json)
    test_app.py     asserts legitimate behavior is preserved (uses PATCHPROOF_BASE_URL)
  poc.txt           the exploit (curl / raw HTTP / nuclei / python)
  fix.patch         a root-cause fix, as a unified diff rooted at the app dir
```

Generate `fix.patch` from a real edit so the context lines are exact:

```bash
cp -r tests/fixtures/<name>/app /tmp/fixgen && cd /tmp/fixgen
git init -q && git add -A && git commit -qm base
# edit the files to fix the vuln
git diff > fix.patch
```

Add the fixture to the `self-verify` job in `.github/workflows/ci.yml` and to
the parametrized list in `tests/test_integration.py`.

## Adding a PoC format or runner

- New PoC format: extend `load_poc` / the parsers in
  `src/patchproof/ingest/normalize.py` and add a unit test in
  `tests/test_ingest.py`.
- New runner backend: implement the `_Base` interface in
  `src/patchproof/sandbox/runner.py` and register it in `make_runner`.

Keep untrusted input (PoC text, HTTP responses) out of any shell command line
and out of LLM prompts — see [SECURITY.md](SECURITY.md).
