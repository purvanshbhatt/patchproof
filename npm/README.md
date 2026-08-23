# patchproof-repro (npm)

Thin npm wrapper around the Python CLI [`patchproof-repro`](https://pypi.org/project/patchproof-repro/).

`npx patchproof` will:

1. Find a Python ≥ 3.11 interpreter (override with `PATCHPROOF_PYTHON`).
2. `pip install --user patchproof-repro` if it's missing (opt out: `PATCHPROOF_SKIP_INSTALL=1`).
3. Forward all arguments to the real `patchproof` CLI.

## Usage

```bash
npx patchproof --help
npx patchproof run   --app ./my-app --poc ./poc.curl
npx patchproof verify --app ./my-app --poc ./poc.curl --patch ./fix.patch
```

Docker is required at run time — the engine executes exploits inside an
ephemeral container. See the [main repo](https://github.com/purvanshbhatt/patchproof)
for the full documentation.
