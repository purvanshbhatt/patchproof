"""Generate a unified diff using LiteLLM.

The prompt asks for a strict unified diff that applies cleanly. We request
JSON in/out so the model is forced to emit `diff` + `explanation` fields and
we can refuse anything that looks like garbage.
"""
from __future__ import annotations

import json
import re

from ..ingest.normalize import PoC
from .locator import PatchTarget

SYSTEM_PROMPT = """You are PatchProof, a security engineer who fixes application \
vulnerabilities with MINIMAL, SURGICAL diffs. You will be shown a single source \
file (with line numbers) and a failing PoC request + response.

You must reply with JSON of the form:
{"diff": "<unified diff>", "explanation": "<one short sentence>"}

Rules:
- Reply ONLY with JSON. No prose, no markdown fences.
- The `diff` MUST be a valid unified diff (`--- a/path`, `+++ b/path`, `@@ ... @@`).
- Keep changes minimal and focused on the sink; do not refactor surrounding code.
- Prefer parameterised queries, allow-lists, input validation, and safe APIs.
- Never introduce new dependencies.
"""


def _build_user_prompt(target: PatchTarget, poc: PoC, red_response: str) -> str:
    file_block = target.file.read_text()
    numbered = "\n".join(
        f"{i + 1:4d}  {line}" for i, line in enumerate(file_block.splitlines())
    )
    req = poc.payload
    return (
        f"Target: {target}\n"
        f"Sink pattern suspected: {target.sink}\n"
        f"PoC request: {json.dumps(req, sort_keys=True)}\n\n"
        f"PoC response (truncated):\n```\n{red_response[:2000]}\n```\n\n"
        f"Full source ({target.file.name}) with line numbers:\n```\n{numbered}\n```\n\n"
        "Return JSON with `diff` and `explanation`."
    )


_DIFF_RE = re.compile(r"```(?:diff)?\s*([\s\S]*?)```")


def _extract_diff(text: str) -> str:
    text = text.strip()
    if text.startswith("{"):
        try:
            data = json.loads(text)
            diff = data.get("diff", "")
            if diff:
                return diff.strip()
        except json.JSONDecodeError:
            pass
    m = _DIFF_RE.search(text)
    if m:
        return m.group(1).strip()
    if text.startswith("---"):
        return text
    return ""


def generate_patch(
    target: PatchTarget,
    poc: PoC,
    red_response: str,
    model: str,
    api_key: str | None = None,
    api_base: str | None = None,
) -> str:
    """Call LiteLLM and return a unified diff string (possibly empty)."""
    try:
        import litellm  # type: ignore
    except Exception:  # pragma: no cover - import guard
        return ""

    user_prompt = _build_user_prompt(target, poc, red_response)

    kwargs: dict = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.0,
    }
    if api_key:
        kwargs["api_key"] = api_key
    if api_base:
        kwargs["api_base"] = api_base

    try:
        resp = litellm.completion(**kwargs)
    except Exception as e:  # pragma: no cover - network/LLM failures
        return _error_diff(str(e))

    try:
        content = resp.choices[0].message["content"] or ""
    except Exception:  # noqa: BLE001
        content = str(resp)
    return _extract_diff(content)


def _error_diff(msg: str) -> str:
    """Return an empty diff (signals retry)."""
    return ""
