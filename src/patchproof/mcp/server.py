"""PatchProof MCP server.

Exposes a single tool `patchproof_run` so MCP-aware editors (Cursor, Claude
Code) can hand a vulnerable file + PoC to the engine and receive a verified
.patch plus an attestation.

Run standalone:
    python -m patchproof.mcp.server

Configure in your MCP client:
    {
      "mcpServers": {
        "patchproof": {
          "command": "python",
          "args": ["-m", "patchproof.mcp.server"],
          "cwd": "<path to your patchproof checkout>"
        }
      }
    }
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

SERVER_NAME = "patchproof"
SERVER_VERSION = "0.1.0"


def _tool_definitions() -> list[dict]:
    return [
        {
            "name": "patchproof_run",
            "description": (
                "Run the PatchProof red→green loop against an app path and PoC. "
                "Returns the verdict, attempt count, and paths to the patch + attestation."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "app_path": {"type": "string", "description": "Path to target app source."},
                    "poc_path": {"type": "string", "description": "Path to PoC exploit file."},
                    "hardcoded_patch": {
                        "type": "string",
                        "description": "Optional diff to verify without LLM.",
                    },
                    "max_attempts": {"type": "integer", "default": 5},
                    "model": {"type": "string", "default": "gpt-4o-mini"},
                },
                "required": ["app_path", "poc_path"],
            },
        },
        {
            "name": "patchproof_verify",
            "description": "Apply a patch and verify it blocks the PoC without regressions.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "app_path": {"type": "string"},
                    "poc_path": {"type": "string"},
                    "patch_path": {"type": "string"},
                },
                "required": ["app_path", "poc_path", "patch_path"],
            },
        },
    ]


async def _dispatch(name: str, arguments: dict) -> dict:
    from ..pipeline import Pipeline, verify_only

    if name == "patchproof_run":
        p = Pipeline(
            app_path=Path(arguments["app_path"]),
            poc=Path(arguments["poc_path"]),
            hardcoded_patch=Path(arguments["hardcoded_patch"]) if arguments.get("hardcoded_patch") else None,
            max_attempts=int(arguments.get("max_attempts", 5)),
            model=arguments.get("model", "gpt-4o-mini"),
        )
        result = p.run()
        return {
            "verdict": "green" if result.patch_path else "red",
            "attempts": result.attempts,
            "patch_path": str(result.patch_path) if result.patch_path else None,
            "attestation_path": str(result.attestation_path) if result.attestation_path else None,
            "artifacts": [str(a) for a in result.artifacts],
        }
    if name == "patchproof_verify":
        rc = verify_only(
            app_path=Path(arguments["app_path"]),
            poc=Path(arguments["poc_path"]),
            patch_file=Path(arguments["patch_path"]),
        )
        return {"returncode": rc, "verdict": "green" if rc == 0 else "failed"}
    raise ValueError(f"unknown tool: {name}")


async def _serve_stdio() -> None:  # pragma: no cover - requires `mcp` extra
    try:
        from mcp import types  # type: ignore
        from mcp.server import Server  # type: ignore
        from mcp.server.stdio import stdio_server  # type: ignore
    except ImportError:
        sys.stderr.write("install the [mcp] extra: pip install 'patchproof[mcp]'\n")
        sys.exit(2)

    server = Server(SERVER_NAME)

    @server.list_tools()
    async def _list() -> list[Any]:
        return _tool_definitions()

    @server.call_tool()
    async def _call(name: str, arguments: dict) -> list[Any]:
        result = await _dispatch(name, arguments)
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main() -> None:
    asyncio.run(_serve_stdio())


if __name__ == "__main__":
    main()
