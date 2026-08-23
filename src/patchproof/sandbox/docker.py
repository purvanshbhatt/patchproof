"""Docker sandbox wrapper: build/run/reload/exec inside an ephemeral container.

Lifecycle:
    Sandbox(...) -> up() -> run_poc()/run_tests()/reload() -> down()

Design:
- Mount the source tree read-write so the hot-reload picks up edits.
- A unique image_tag per run so concurrent runs don't collide.
- `_wait_ready` polls the root URL; framework-specific readiness can be
  customized by extending AppSpec.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from .app_spec import AppSpec

DOCKERFILE_TMPL = """FROM {base_image}
WORKDIR /app
COPY . /app
RUN {install_cmd}
EXPOSE {port}
CMD {run_cmd}
"""


_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "dist", "build", ".egg-info", "patchproof-out"}


@dataclass
class Sandbox:
    app_path: Path
    spec: AppSpec
    out_dir: Path
    container_name: str = ""
    image_tag: str = ""
    host: str = "127.0.0.1"
    port: int = 0
    container_port: int = 0

    def __post_init__(self) -> None:
        if not self.container_name:
            self.container_name = f"patchproof-{uuid.uuid4().hex[:8]}"
        if not self.image_tag:
            self.image_tag = f"patchproof-img-{uuid.uuid4().hex[:8]}"
        if not self.port:
            self.port = self.spec.port
        if not self.container_port:
            self.container_port = self.spec.port

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    # ------------------------------------------------------------------ up

    def up(self) -> None:
        dockerfile = DOCKERFILE_TMPL.format(
            base_image=self.spec.base_image,
            install_cmd=self.spec.install_cmd,
            run_cmd=self.spec.run_cmd,
            port=self.spec.port,
        )
        self._check_docker()
        self._build(dockerfile)
        self._run()
        self._wait_ready()

    def _check_docker(self) -> None:
        if shutil.which("docker") is None:
            raise RuntimeError("docker CLI not found on PATH")
        try:
            subprocess.run(["docker", "info"], check=True, capture_output=True, timeout=10)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"docker daemon unreachable: {e.stderr.decode(errors='ignore')}") from e

    def _build(self, dockerfile: str) -> None:
        ctx = self.out_dir / "buildctx"
        if ctx.exists():
            shutil.rmtree(ctx)
        ctx.mkdir(parents=True, exist_ok=True)
        (ctx / "Dockerfile").write_text(dockerfile)
        for p in self.app_path.rglob("*"):
            if not p.is_file():
                continue
            if any(part in _SKIP_DIRS for part in p.parts):
                continue
            try:
                rel = p.relative_to(self.app_path)
            except ValueError:
                continue
            dest = ctx / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, dest)
        subprocess.run(
            ["docker", "build", "-t", self.image_tag, str(ctx)],
            check=True,
            capture_output=True,
        )

    def _run(self) -> None:
        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                self.container_name,
                "-p",
                f"{self.port}:{self.container_port}",
                "-v",
                f"{self.app_path}:/app",
                self.image_tag,
            ],
            check=True,
            capture_output=True,
        )

    def _wait_ready(self, timeout: float = 60.0) -> None:
        import httpx

        deadline = time.time() + timeout
        last_err: Exception | None = None
        while time.time() < deadline:
            try:
                r = httpx.get(self.url, timeout=2.0)
                if r.status_code < 500:
                    return
            except Exception as e:  # noqa: BLE001
                last_err = e
            time.sleep(1.0)
        raise RuntimeError(f"container did not become ready in {timeout}s: {last_err}")

    # ------------------------------------------------------------------ ops

    def reload(self) -> None:
        """Touch the entry file so the autoreloader picks it up; restart as fallback."""
        subprocess.run(
            ["docker", "exec", self.container_name, "sh", "-c", self.spec.reload_cmd],
            check=False,
            capture_output=True,
        )
        time.sleep(1.0)
        try:
            subprocess.run(
                ["docker", "restart", self.container_name],
                check=True,
                capture_output=True,
                timeout=20,
            )
        except subprocess.CalledProcessError:
            pass
        self._wait_ready()

    def run_poc(self, poc) -> object:
        from ..ingest.normalize import PoC
        if isinstance(poc, PoC) and poc.kind == "python":
            return self._run_python_poc(poc)
        return poc.run(self.url)

    def _run_python_poc(self, poc) -> object:
        """Run an in-process Python PoC against the sandboxed URL."""
        from ..ingest.normalize import PoCResult

        script = poc.payload.get("script", "")
        env = os.environ.copy()
        env["PATCHPROOF_BASE_URL"] = self.url
        try:
            proc = subprocess.run(
                ["python", "-c", script],
                capture_output=True,
                text=True,
                env=env,
                timeout=15,
            )
            text = (proc.stdout or "") + (proc.stderr or "")
            succeeded = ("EXPLOIT_OK" in text) or (
                proc.returncode == 0 and "EXPLOIT_FAIL" not in text
            )
            return PoCResult(
                request={"script": script[:200]},
                response_status=0,
                response_text=text[:4000],
                response_headers={},
                exploit_succeeded=succeeded,
            )
        except subprocess.TimeoutExpired:
            return PoCResult(
                request={"script": script[:200]},
                response_status=0,
                response_text="timeout",
                response_headers={},
                exploit_succeeded=True,
            )

    def run_tests(self) -> bool:
        """Run the framework's test suite inside the container."""
        from ..regression.runner import run_tests

        return run_tests(self.container_name, self.spec)

    def collect_logs(self) -> str:
        from ..regression.runner import collect_logs

        return collect_logs(self.container_name)

    # ------------------------------------------------------------------ art

    def write_regression_test(self, poc) -> Path | None:
        """Emit a regression test that locks the exploit scenario."""
        target_dir = self.app_path / "tests" if (self.app_path / "tests").exists() else self.app_path
        if self.spec.runtime == "python":
            test_path = target_dir / "test_security_patchproof.py"
            body = _python_regression_body(poc)
            test_path.write_text(body)
            return test_path
        if self.spec.runtime == "node":
            test_path = target_dir / "test_security_patchproof.js"
            body = _node_regression_body(poc)
            test_path.write_text(body)
            return test_path
        return None

    def target_sha(self) -> str:
        h = hashlib.sha256()
        for p in sorted(self.app_path.rglob("*")):
            if p.is_file() and "__pycache__" not in str(p) and "node_modules" not in str(p):
                rel = p.relative_to(self.app_path)
                h.update(str(rel).encode())
                h.update(p.read_bytes())
        return h.hexdigest()

    def down(self) -> None:
        subprocess.run(
            ["docker", "rm", "-f", self.container_name],
            check=False,
            capture_output=True,
        )


# ---------------------------------------------------------------------------
# Regression test templates
# ---------------------------------------------------------------------------


def _python_regression_body(poc) -> str:
    import json as _json

    req = poc.payload
    method = (req.get("method") or "GET").upper()
    url = req.get("url", "/")
    headers = req.get("headers") or {}
    body = req.get("body")
    return (
        '"""Auto-generated by PatchProof. Locks the exploit scenario in CI."""\n'
        "import os\n"
        "import httpx\n\n"
        f"BASE = os.environ.get('PATCHPROOF_BASE_URL', 'http://localhost:{poc.payload.get('_port', 8000)}')\n"
        f"METHOD = {method!r}\n"
        f"URL = {url!r}\n"
        f"HEADERS = {_json.dumps(headers)}\n"
        f"BODY = {body!r}\n\n"
        "def test_exploit_blocked():\n"
        "    r = httpx.request(METHOD, BASE + URL, headers=HEADERS, content=BODY, timeout=5.0)\n"
        "    assert r.status_code < 500, f'exploit returned 5xx: {r.status_code}'\n"
        "    assert 'EXPLOIT_LEAK' not in r.text, 'exploit signature still present in response'\n"
    )


def _node_regression_body(poc) -> str:

    req = poc.payload
    method = (req.get("method") or "GET").lower()
    url = req.get("url", "/")
    body = req.get("body")
    return (
        "// Auto-generated by PatchProof. Locks the exploit scenario in CI.\n"
        "const http = require('http');\n"
        "const { URL } = require('url');\n\n"
        f"const BASE = process.env.BASE || 'http://localhost:{poc.payload.get('_port', 3000)}';\n"
        f"const METHOD = {method!r};\n"
        f"const URL_PATH = {url!r};\n"
        f"const BODY = {body!r};\n\n"
        "test('exploit blocked', (done) => {\n"
        "  const u = new URL(URL_PATH, BASE);\n"
        "  const req = http.request({ hostname: u.hostname, port: u.port, path: u.pathname + u.search, method: METHOD }, (res) => {\n"
        "    let data = '';\n"
        "    res.on('data', (c) => (data += c));\n"
        "    res.on('end', () => {\n"
        "      expect(res.statusCode).toBeLessThan(500);\n"
        "      expect(data).not.toMatch(/EXPLOIT_LEAK/);\n"
        "      done();\n"
        "    });\n"
        "  });\n"
        "  if (BODY) req.write(BODY);\n"
        "  req.end();\n"
        "});\n"
    )
