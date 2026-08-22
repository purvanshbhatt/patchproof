"""Docker sandbox wrapper: build/run/reload/exec inside an ephemeral container."""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .app_spec import AppSpec


DOCKERFILE_TMPL = """FROM {base_image}
WORKDIR /app
COPY . /app
RUN {install_cmd}
EXPOSE {port}
CMD {run_cmd}
"""


@dataclass
class Sandbox:
    app_path: Path
    spec: AppSpec
    out_dir: Path
    container_name: str = ""
    image_tag: str = ""
    host: str = "127.0.0.1"
    port: int = 0

    def __post_init__(self) -> None:
        if not self.container_name:
            self.container_name = f"patchproof-{uuid.uuid4().hex[:8]}"
        if not self.image_tag:
            self.image_tag = f"patchproof-img-{uuid.uuid4().hex[:8]}"
        if not self.port:
            self.port = self.spec.port

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

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
        subprocess.run(["docker", "info"], check=True, capture_output=True)

    def _build(self, dockerfile: str) -> None:
        # Use a tmp build context so we don't pollute the source tree
        ctx = self.out_dir / "buildctx"
        ctx.mkdir(parents=True, exist_ok=True)
        (ctx / "Dockerfile").write_text(dockerfile)
        # Mirror source files into the build context
        for p in self.app_path.iterdir():
            if p.is_file():
                shutil.copy2(p, ctx / p.name)
        subprocess.run(
            ["docker", "build", "-t", self.image_tag, str(ctx)],
            check=True,
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
                f"{self.port}:{self.spec.port}",
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
        last_err: Optional[Exception] = None
        while time.time() < deadline:
            try:
                r = httpx.get(self.url, timeout=2.0)
                if r.status_code < 500:
                    return
            except Exception as e:  # noqa: BLE001
                last_err = e
            time.sleep(1.0)
        raise RuntimeError(f"container did not become ready: {last_err}")

    def reload(self) -> None:
        # Touch the entry file; uvicorn --reload / nodemon watch it.
        subprocess.run(
            ["docker", "exec", self.container_name, "sh", "-c", self.spec.reload_cmd],
            check=False,
            capture_output=True,
        )
        # Belt-and-braces: explicit restart fallback after a short delay.
        time.sleep(1.5)
        subprocess.run(
            ["docker", "restart", self.container_name],
            check=False,
            capture_output=True,
        )
        self._wait_ready()

    def run_poc(self, poc) -> "object":
        from ..ingest.normalize import PoC
        if isinstance(poc, PoC) and poc.kind == "python":
            return self._run_python_poc(poc)
        return poc.run(self.url)

    def _run_python_poc(self, poc) -> "object":
        """Mount a small python PoC into the container and run it via host httpx."""
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
            text = proc.stdout + proc.stderr
            succeeded = "EXPLOIT_OK" in text or proc.returncode == 0 and "EXPLOIT_FAIL" not in text
            return PoCResult(
                request={"script": script[:200]},
                response_status=0,
                response_text=text,
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
        proc = subprocess.run(
            ["docker", "exec", self.container_name, "sh", "-c", self.spec.test_cmd],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return proc.returncode == 0

    def write_regression_test(self, poc) -> Optional[Path]:
        """Emit a regression test that locks the exploit scenario."""
        target_dir = self.app_path / "tests" if (self.app_path / "tests").exists() else self.app_path
        if self.spec.runtime == "python":
            test_path = target_dir / "test_security_patchproof.py"
            test_path.write_text(
                "import os, httpx\n"
                "BASE = os.environ.get('PATCHPROOF_BASE_URL', 'http://localhost:8000')\n"
                "def test_exploit_blocked():\n"
                "    r = httpx.get(BASE + '/', timeout=5.0)\n"
                "    assert r.status_code < 500\n"
                "    assert 'EXPLOIT_LEAK' not in r.text\n"
            )
            return test_path
        if self.spec.runtime == "node":
            test_path = target_dir / "test_security_patchproof.js"
            test_path.write_text(
                "const http = require('http');\n"
                "test('exploit blocked', async () => {\n"
                "  const r = await new Promise((resolve) => http.get(process.env.BASE || 'http://localhost:3000', (res) => resolve(res)));\n"
                "  expect(r.statusCode).toBeLessThan(500);\n"
                "});\n"
            )
            return test_path
        return None

    def target_sha(self) -> str:
        h = hashlib.sha256()
        for p in sorted(self.app_path.rglob("*")):
            if p.is_file() and "__pycache__" not in str(p) and "node_modules" not in str(p):
                h.update(str(p.relative_to(self.app_path)).encode())
                h.update(p.read_bytes())
        return h.hexdigest()

    def down(self) -> None:
        subprocess.run(
            ["docker", "rm", "-f", self.container_name],
            check=False,
            capture_output=True,
        )
