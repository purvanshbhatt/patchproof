# Demo

## Recording the README GIF

```bash
# 1. Install VHS (https://github.com/charmbracelet/vhs)
winget install charmbracelet.vhs   # or: brew install vhs

# 2. Start Docker, then record
vhs demo/demo.tape
```

`demo/demo.tape` types the command, waits through each pipeline stage
(sandbox → red → patch loop → green), and writes `demo/demo.gif`.

The GIF is embedded at the top of the main README — commit it after recording:

```bash
git add demo/demo.gif && git commit -m "docs: record demo GIF" && git push
```

## What viewers see

1. **Sandbox** — ephemeral Docker container builds and serves the vulnerable FastAPI app.
2. **RED** — `curl "?id=' OR '1'='1'"` returns `EXPLOIT_LEAK: admin_password=supersecret`.
3. **Patch loop** — diff applied, app hot-reloaded inside the container.
4. **GREEN** — same PoC now returns `400 Invalid Input`; regression suite passes;
   `attestation.json` + `fix.patch` land in `patchproof-out/<run-id>/`.
