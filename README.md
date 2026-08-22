# PatchProof

Deterministic exploit repro + AI patch verification engine.

## Install

```bash
uv pip install -e .
# or: pipx install .
```

Requires Docker daemon running.

## Usage

```bash
patchproof run --app ./tests/fixtures/vuln-fastapi-sqli/app \
               --poc ./tests/fixtures/vuln-fastapi-sqli/poc.txt \
               --hardcoded-patch ./tests/fixtures/vuln-fastapi-sqli/fix.patch
```

## Architecture

See `src/patchproof/pipeline.py` for the full red→green loop.
