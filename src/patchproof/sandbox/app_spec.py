"""Detect target app runtime and pick base image + reload command."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class AppSpec:
    runtime: str  # "python" | "node"
    framework: str  # "fastapi" | "flask" | "django" | "express" | "fastify" | "unknown"
    base_image: str
    install_cmd: str
    run_cmd: str
    reload_cmd: str  # signal that triggers a restart inside the container
    port: int
    test_cmd: str


def detect_app_spec(app_path: Path) -> AppSpec:
    if (app_path / "package.json").exists():
        return _node_spec(app_path)
    return _python_spec(app_path)


def _python_spec(app_path: Path) -> AppSpec:
    reqs = (app_path / "requirements.txt").read_text().lower() if (app_path / "requirements.txt").exists() else ""
    framework = "unknown"
    if "fastapi" in reqs:
        framework = "fastapi"
    elif "flask" in reqs:
        framework = "flask"
    elif "django" in reqs:
        framework = "django"

    if framework == "fastapi":
        return AppSpec(
            runtime="python",
            framework="fastapi",
            base_image="python:3.12-slim",
            install_cmd="pip install --no-cache-dir -r requirements.txt",
            run_cmd="uvicorn app:app --host 0.0.0.0 --port 8000 --reload",
            reload_cmd="touch /app/app.py",
            port=8000,
            test_cmd="pytest -q",
        )
    if framework == "flask":
        return AppSpec(
            runtime="python",
            framework="flask",
            base_image="python:3.12-slim",
            install_cmd="pip install --no-cache-dir -r requirements.txt",
            run_cmd="flask --app app run --host 0.0.0.0 --port 5000 --reload",
            reload_cmd="touch /app/app.py",
            port=5000,
            test_cmd="pytest -q",
        )
    return AppSpec(
        runtime="python",
        framework=framework,
        base_image="python:3.12-slim",
        install_cmd="pip install --no-cache-dir -r requirements.txt",
        run_cmd="python app.py",
        reload_cmd="touch /app/app.py",
        port=8000,
        test_cmd="pytest -q",
    )


def _node_spec(app_path: Path) -> AppSpec:
    pkg = (app_path / "package.json").read_text().lower()
    framework = "express" if "express" in pkg else "fastify" if "fastify" in pkg else "node"
    if framework == "express":
        return AppSpec(
            runtime="node",
            framework="express",
            base_image="node:20-slim",
            install_cmd="npm install --silent",
            run_cmd="npx nodemon --watch . app.js",
            reload_cmd="touch /app/app.js",
            port=3000,
            test_cmd="npm test --silent",
        )
    return AppSpec(
        runtime="node",
        framework=framework,
        base_image="node:20-slim",
        install_cmd="npm install --silent",
        run_cmd="node app.js",
        reload_cmd="touch /app/app.js",
        port=3000,
        test_cmd="npm test --silent",
    )
