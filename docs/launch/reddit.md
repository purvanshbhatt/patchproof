# Reddit drafts

## r/netsec — title

We built an open-source engine that verifies security patches by re-executing the original PoC in Docker (red → green, with signed attestations)

## r/netsec — body

**The gap:** most vulnerability reports end like this — pentester hands over a
PoC, developer writes a patch, and *nobody re-runs the exploit* to confirm
it's actually blocked. Static analyzers can't do it; they don't execute code.

**PatchProof (Apache-2.0)** automates exactly that loop:

1. Normalize any PoC input: curl, raw HTTP, Nuclei JSON template, or Python script.
2. Build your app into an ephemeral container; execute the PoC → RED baseline.
3. LLM (via LiteLLM, bring your own key incl. local Ollama) locates the sink
   and drafts a minimal diff.
4. Hot-reload inside the container, re-execute the identical PoC.
5. Iterate until blocked (GREEN), then run the project's native test suite.
6. Emit: merge-ready `.patch`, auto-generated regression test locking the
   scenario into CI, SHA-256 attestation (optional ed25519 signature).

Threat model notes: everything runs locally against localhost containers;
the only egress is your chosen LLM endpoint. `--hardcoded-patch` mode is
fully offline and still produces attestations — useful as a CI gate for
human-written fixes.

Repo: https://github.com/purvanshbhatt/patchproof
PyPI: https://pypi.org/project/patchproof-repro/

Feedback wanted on: sandbox hardening (currently one container, no network
isolation yet), Nuclei matcher coverage, and what evidence format your
compliance team would want.

---

## r/Python — title

I built a tool that takes a PoC exploit, patches your FastAPI/Flask/Express app with an LLM, and proves the fix works by re-running the attack until it fails

## r/Python — body

TL;DR: `pip install patchproof-repro`, point it at a vulnerable app + a curl
command, and watch red turn green:

```bash
patchproof run --app ./my-app --poc ./poc.txt
```

What happens under the hood:

- **PoC ingestion:** parses curl commands, raw HTTP request dumps, and Nuclei
  JSON templates into a normalized executable assertion.
- **Ephemeral sandbox:** detects your stack (FastAPI/Flask/Django/Express)
  from requirements/package.json, builds a throwaway Docker image, mounts
  your source read-write so hot-reload picks up edits.
- **AI patch loop:** tree-sitter-assisted locator finds the vulnerable
  function, LiteLLM drafts a unified diff under a strict JSON contract,
  applied via `git apply` with snapshot-based rollback between attempts
  (LLM diffs fail to apply more often than you'd think — we handle it).
- **Regression gate:** runs your existing pytest/npm suite inside the same
  container before declaring victory.
- **Artifacts:** `fix.patch`, `test_security_regression.py`, and an
  attestation.json you can drop into audit evidence.

It also ships as a GitHub Action (`uses: purvanshbhatt/patchproof@v0.1.0`),
a pre-commit hook, and an MCP server so Cursor/Claude Code can call it mid-session.

Repo + demo: https://github.com/purvanshbhatt/patchproof

Happy to go deep on the diff-applier implementation (hand-rolled hunk parser
with context-line tolerance) if anyone's curious.
