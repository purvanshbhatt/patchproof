# awesome-list PR draft

Target lists:
- https://github.com/cckuailong/awesome-ai-security (AI security tools)
- https://github.com/joe-shenouda/awesome-cyber-skills
- https://github.com/enaqx/awesome-pentest (Defense section)
- https://github.com/agentifui/awesome-mcp-servers (Security category)

## PR body

Adds **PatchProof** to the AI-Assisted Defense / Code Review section.

PatchProof is a deterministic exploit-repro and AI patch-verification engine.
It ingests a PoC exploit (curl / raw HTTP / Nuclei JSON / Python), reproduces
it against the target app in an ephemeral Docker container (RED), uses an LLM
to draft a minimal fix, hot-reloads, and re-executes the identical PoC until
blocked (GREEN) — then runs the project's test suite and emits a merge-ready
`.patch`, an auto-generated regression test, and a SHA-256 attestation
(optional ed25519-signed). Ships as CLI (PyPI/npm), Python library, GitHub
Action, pre-commit hook, and MCP server.

- Repo: https://github.com/purvanshbhatt/patchproof
- PyPI: https://pypi.org/project/patchproof-repro/
- License: Apache-2.0

Suggested entry (matches list style):

```
- [PatchProof](https://github.com/purvanshbhatt/patchproof) - Verifies security patches by re-executing PoC exploits in an ephemeral sandbox until red turns green; emits merge-ready diffs, regression tests, and signed attestations. ![Apache2](https://img.shields.io/badge/license-Apache--2.0-blue)
```
