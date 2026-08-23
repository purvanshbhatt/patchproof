# Show HN draft

## Title

Show HN: PatchProof – AI agent that verifies security patches by re-executing PoC exploits

## Text post

Hi HN! We built PatchProof, an open-source engine that closes the loop between
"we found a vulnerability" and "we proved the fix works."

**The problem:** offensive AI tools (PentestGPT, Strix) find vulnerabilities
and generate PoCs — then stop. Defensive tools (Copilot, SonarQube,
Dependabot) suggest fixes — but can't prove the fix actually blocks the
exploit at runtime, or that it didn't break the app. Security teams re-test
manually; developers ship patches that silently regress.

**What PatchProof does (all local):**

1. Ingests any PoC — a curl command, raw HTTP dump, Nuclei JSON template, or Python script.
2. Spins up your app in an ephemeral Docker container.
3. Executes the PoC to confirm it reproduces (RED).
4. Uses an LLM via LiteLLM to locate the vulnerable sink and draft a minimal unified diff.
5. Hot-reloads the app inside the container and re-executes the *exact same* PoC.
6. Iterates (max N attempts) until the exploit is blocked (GREEN), then runs
   your test suite to guarantee zero regression.

Artifacts emitted per run: a merge-ready `.patch`, an auto-generated pytest
regression test that locks the exploit scenario into CI forever, and a JSON
attestation with SHA-256 of target + PoC (optionally ed25519-signed).

It's MIT-style Apache-2.0, installable via `pip install patchproof-repro` or
`npx patchproof`, usable as a library, a pre-commit hook, a GitHub Action, and
an MCP server for Cursor/Claude Code.

Try it in 60 seconds against the bundled vulnerable FastAPI fixture:

    pip install patchproof-repro
    patchproof run --app ./tests/fixtures/vuln-fastapi-sqli/app \
                   --poc ./tests/fixtures/vuln-fastapi-sqli/poc.txt

Repo: https://github.com/purvanshbhatt/patchproof

Happy to answer questions about the sandbox design, the diff-applier edge
cases (LLMs emit surprisingly creative diffs), or why we verify by
re-execution instead of trusting static analysis.

## First comment (posting tips)

- Post Tuesday–Thursday, 8–10am ET.
- Lead with the demo GIF if recorded (`demo/demo.gif`).
- Disclose honestly: LLM mode needs an API key; `--hardcoded-patch` mode is fully offline.
