# Security model

PatchProof runs **untrusted inputs**: a target application that is known to be
vulnerable, and a proof-of-concept exploit. It is built so that doing so does
not compromise the host or leak data.

## Threat model

| Input | Trust | Handling |
|-------|-------|----------|
| Target app source | semi-trusted (maintainer's own code) | copied to a throwaway git working copy; the user's tree is never modified |
| PoC file | **untrusted** | parsed as data; never executed as a host shell command; HTTP fields passed to the sandbox via environment variables, never interpolated into a command line |
| HTTP response body | **untrusted** | used only for the pass/fail oracle; never injected verbatim into an LLM prompt |
| LLM-generated diff | **untrusted** | applied with `git apply` to the working copy only; rolled back on failure; the real patch shown to the user is the diff against baseline |

## PoC-as-data

The LLM patch generator (`patchproof.patch.llm`) never receives the raw PoC or
the raw HTTP response. It receives the application's own source plus a
structured, length-capped summary (method, path, status code, matched marker
names) inside an explicit data fence with the instruction that fenced content is
data, not instructions. This blocks indirect prompt injection carried in PoC
bodies, headers, or crafted responses.

## Sandbox posture (Docker runner)

The Docker runner (`--runner docker`) starts the target with:

- `--network none` — the app cannot reach the network and is **not reachable
  from the host** (no published port). PoCs are replayed from *inside* the
  container against container-localhost.
- `--cap-drop ALL` and `--security-opt no-new-privileges`.
- No Docker socket mounted.
- An ephemeral container (`--rm`) removed on exit.

The `local` runner (`--runner local`) trades isolation for portability: it runs
the app as a subprocess in a per-run virtualenv. Use it for CI and for targets
you already trust; use `docker` for anything you do not.

## What a green verdict does and does not mean

A green run proves:

- the supplied exploit no longer succeeds,
- generated variant PoCs (encoding/case/comment mutations) also no longer
  succeed, and
- the application's existing tests still pass.

It does **not** prove the patch is semantically correct or complete. Published
research (DARPA AIxCC 2025; Team Atlanta 2026; 1Password FLAWED 2026) shows a
meaningful fraction of patches that pass exploit-replay and tests are still
wrong. The attestation records `semantic_review: none` for this reason.
Independent human review remains required before shipping.

## Reporting a vulnerability

Open a private security advisory on the repository, or email the maintainer.
Please do not file public issues for undisclosed vulnerabilities.
