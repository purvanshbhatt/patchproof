# PatchProof Roadmap

Status: v0.1.0 — single-container local execution, live on
[GitHub](https://github.com/purvanshbhatt/patchproof) /
[PyPI](https://pypi.org/project/patchproof-repro/) /
[npm](https://www.npmjs.com/package/patchproof-repro).

## Community tier (open source, Apache-2.0) — free forever

- [x] PoC ingestion: curl, raw HTTP, Nuclei JSON, Python scripts
- [x] Ephemeral Docker sandbox (FastAPI / Flask / Django / Express detection)
- [x] Red baseline → AI patch loop → Green verdict
- [x] Regression suite gate (`pytest` / `npm test`) inside the container
- [x] Artifacts: `.patch`, auto-generated regression test, SHA-256 attestation
- [x] Optional ed25519-signed attestations
- [x] GitHub Action (`action.yml`) + pre-commit hook (`.pre-commit-hooks.yaml`)
- [x] MCP server for Cursor / Claude Code
- [ ] Network isolation for the sandbox container (egress deny by default)
- [ ] Multi-file diff support in the hand-rolled applier
- [ ] Nuclei matcher coverage: dsl, regex, multi-status conditions
- [ ] Go / Java runtime detection
- [ ] Local LLM presets (Ollama one-liner config)

## Enterprise tier (paid SaaS)

### Phase 1 — Complex environments
- Kubernetes-native sandboxes (multi-container: app + Postgres + Redis + auth)
- Per-run network topology definitions (`patchproof.yaml` env graph)
- Snapshot/restore between patch attempts at the namespace level

### Phase 2 — Autonomous remediation bots
- GitHub/GitLab app that watches vulnerability reports and open PRs
- Cloud workers run PatchProof; bot opens PRs with:
  - execution proof (recorded terminal session)
  - signed attestation attached as a verified commit comment
- Policy engine: severity thresholds, auto-merge rules, reviewer routing

### Phase 3 — Compliance & audit
- SOC 2 / ISO 27001 evidence exports mapping VAPT findings → verified fixes
- Long-term attestation storage with transparency-log-style append-only hashes
- SIEM webhooks (Splunk, Sentinel) for remediation events

## Non-goals

- Replacing SAST/DAST scanners — PatchProof consumes their findings.
- Running untrusted PoCs on developer laptops without Docker isolation warnings.
- Fully autonomous merging without human review.
