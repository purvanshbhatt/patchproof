"""Detect target app runtime, web framework, and entrypoint."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_PY_ENTRY = re.compile(r"^\s*(\w+)\s*=\s*(FastAPI|Flask)\s*\(", re.MULTILINE)


@dataclass
class AppSpec:
    runtime: str  # "python" | "node"
    framework: str  # fastapi | flask | express | fastify | unknown
    base_image: str
    install_cmd: str
    port: int
    test_cmd: str
    entry_file: str  # e.g. "main.py" | "app.js"
    app_var: str  # ASGI/WSGI callable name, e.g. "app"
    asgi: bool  # True => served with uvicorn

    @property
    def module(self) -> str:
        return self.entry_file.rsplit(".", 1)[0]

    def local_run_cmd(self, host: str, port: int) -> list[str]:
        # python entries use `python -m <tool>` so no console-script on PATH is needed.
        if self.runtime == "python" and self.framework == "fastapi":
            return ["python", "-m", "uvicorn", f"{self.module}:{self.app_var}",
                    "--host", host, "--port", str(port)]
        if self.runtime == "python" and self.framework == "flask":
            return ["python", "-m", "flask", "--app", self.module, "run",
                    "--host", host, "--port", str(port)]
        if self.runtime == "python":
            return ["python", self.entry_file]
        return ["node", self.entry_file]

    def container_run_cmd(self, port: int) -> str:
        if self.runtime == "python" and self.framework == "fastapi":
            return f"uvicorn {self.module}:{self.app_var} --host 0.0.0.0 --port {port}"
        if self.runtime == "python" and self.framework == "flask":
            return f"flask --app {self.module} run --host 0.0.0.0 --port {port}"
        if self.runtime == "python":
            return f"python {self.entry_file}"
        return f"node {self.entry_file}"


def _find_python_entry(app_path: Path) -> tuple[str, str, str]:
    """Return (entry_file, app_var, framework) by scanning for a FastAPI/Flask app."""
    candidates = sorted(app_path.rglob("*.py"), key=lambda p: (p.name != "main.py", p.name != "app.py", str(p)))
    for p in candidates:
        if "__pycache__" in str(p) or p.name.startswith("test_"):
            continue
        try:
            text = p.read_text()
        except Exception:
            continue
        m = _PY_ENTRY.search(text)
        if m:
            var, fw = m.group(1), m.group(2).lower()
            return p.relative_to(app_path).as_posix(), var, fw
    # Fallback: first .py file, run directly.
    first = next((p for p in candidates if "__pycache__" not in str(p)), None)
    return (first.relative_to(app_path).as_posix() if first else "app.py", "app", "unknown")


def detect_app_spec(app_path: Path) -> AppSpec:
    app_path = Path(app_path)
    if (app_path / "package.json").exists():
        return _node_spec(app_path)
    return _python_spec(app_path)


def _python_spec(app_path: Path) -> AppSpec:
    entry, var, fw = _find_python_entry(app_path)
    reqs_path = app_path / "requirements.txt"
    reqs = reqs_path.read_text().lower() if reqs_path.exists() else ""
    if fw == "unknown":
        if "fastapi" in reqs:
            fw = "fastapi"
        elif "flask" in reqs:
            fw = "flask"
    port = 8000 if fw == "fastapi" else 5000 if fw == "flask" else 8000
    return AppSpec(
        runtime="python",
        framework=fw,
        base_image="python:3.12-slim",
        install_cmd="pip install --no-cache-dir -r requirements.txt",
        port=port,
        test_cmd="python -m pytest -q -p no:cacheprovider",
        entry_file=entry,
        app_var=var,
        asgi=(fw == "fastapi"),
    )


def _node_spec(app_path: Path) -> AppSpec:
    pkg = (app_path / "package.json").read_text().lower()
    fw = "express" if "express" in pkg else "fastify" if "fastify" in pkg else "node"
    entry = "app.js" if (app_path / "app.js").exists() else (
        "server.js" if (app_path / "server.js").exists() else "index.js"
    )
    return AppSpec(
        runtime="node",
        framework=fw,
        base_image="node:20-slim",
        install_cmd="npm install --silent",
        port=3000,
        test_cmd="npm test --silent",
        entry_file=entry,
        app_var="app",
        asgi=False,
    )
