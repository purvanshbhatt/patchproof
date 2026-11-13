"""Sandbox runners: serve a target app, replay PoCs, run regression tests.

Two backends share one interface:

  LocalRunner  - a subprocess in a per-run venv. No isolation; used for CI and
                 machines without Docker. Fast and deterministic.
  DockerRunner - an ephemeral container. Isolation for untrusted targets.
                 Runs with --network none by default (no egress), no Docker
                 socket mounted, and read-only-ish bind of a working copy.

Both operate on a *working copy* of the app (never the user's source tree), so
patches are applied and rolled back without touching the original.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from ..ingest.normalize import ExploitResult, PoC
from .app_spec import AppSpec


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(["docker", "info"], check=True, capture_output=True, timeout=15)
        return True
    except Exception:
        return False


@dataclass
class _Base:
    workdir: Path  # working copy of the app
    spec: AppSpec
    host: str = "127.0.0.1"
    port: int = 0

    def __post_init__(self) -> None:
        self.workdir = Path(self.workdir).resolve()
        if not self.port:
            self.port = free_port()

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def run_poc(self, poc: PoC) -> ExploitResult:
        if poc.kind == "python":
            return self._run_python_poc(poc)
        return poc.run_http(self.base_url)

    def _wait_ready(self, timeout: float = 60.0) -> None:
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            if not self._proc_alive():
                raise RuntimeError(f"app process exited early:\n{self._logs()}")
            try:
                r = httpx.get(self.base_url, timeout=2.0)
                if r.status_code < 500:
                    return
            except Exception as e:  # noqa: BLE001
                last = e
            time.sleep(0.5)
        raise RuntimeError(f"app did not become ready in {timeout}s: {last}\n{self._logs()}")

    # Subclass hooks ------------------------------------------------------- #
    def up(self) -> None: ...
    def reload(self) -> None: ...
    def down(self) -> None: ...
    def run_tests(self) -> tuple[bool, str]: ...
    def _run_python_poc(self, poc: PoC) -> ExploitResult: ...
    def _proc_alive(self) -> bool:
        return True
    def _logs(self) -> str:
        return ""


# --------------------------------------------------------------------------- #
@dataclass
class LocalRunner(_Base):
    _venv: Path | None = field(default=None, init=False)
    _proc: subprocess.Popen | None = field(default=None, init=False)
    _log_path: Path | None = field(default=None, init=False)

    def _py(self) -> str:
        bindir = "Scripts" if os.name == "nt" else "bin"
        return str(self._venv / bindir / "python")

    def _bin(self, name: str) -> str:
        bindir = "Scripts" if os.name == "nt" else "bin"
        cand = self._venv / bindir / name
        return str(cand) if cand.exists() else name

    def up(self) -> None:
        self._venv = self.workdir.parent / "venv"
        if not self._venv.exists():
            subprocess.run([sys.executable, "-m", "venv", str(self._venv)], check=True, capture_output=True)
        reqs = self.workdir / "requirements.txt"
        pip = self._bin("pip")
        if reqs.exists():
            subprocess.run([pip, "install", "--disable-pip-version-check", "-q", "-r", str(reqs)],
                           check=True, capture_output=True)
        subprocess.run([pip, "install", "--disable-pip-version-check", "-q", "pytest", "httpx"],
                       check=False, capture_output=True)
        self._start()
        self._wait_ready()

    def _start(self) -> None:
        cmd = self.spec.local_run_cmd(self.host, self.port)
        if cmd[0] == "python":
            cmd[0] = self._py()
        self._log_path = self.workdir.parent / "server.log"
        logf = open(self._log_path, "wb")
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        self._proc = subprocess.Popen(cmd, cwd=str(self.workdir), stdout=logf, stderr=subprocess.STDOUT, env=env)

    def reload(self) -> None:
        self._stop_proc()
        self._start()
        self._wait_ready()

    def _stop_proc(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None

    def run_tests(self) -> tuple[bool, str]:
        if not list(self.workdir.rglob("test_*.py")) and not list(self.workdir.rglob("*_test.py")):
            return True, "no tests found (skipped)"
        env = os.environ.copy()
        env["PATCHPROOF_BASE_URL"] = self.base_url
        proc = subprocess.run([self._py(), "-m", "pytest", "-q", "-p", "no:cacheprovider"],
                              cwd=str(self.workdir), capture_output=True, text=True, env=env, timeout=180)
        return proc.returncode == 0, (proc.stdout + proc.stderr)[-4000:]

    def _run_python_poc(self, poc: PoC) -> ExploitResult:
        env = os.environ.copy()
        env["PATCHPROOF_BASE_URL"] = self.base_url
        script = poc.payload.get("script", "")
        try:
            proc = subprocess.run([self._bin("python"), "-c", script],
                                  capture_output=True, text=True, env=env, timeout=30)
            out = proc.stdout + proc.stderr
            # Explicit protocol: script prints EXPLOIT_OK / EXPLOIT_FAIL.
            if "EXPLOIT_OK" in out:
                ok = True
            elif "EXPLOIT_FAIL" in out:
                ok = False
            else:
                ok = poc.oracle.judge(0, out)
            return ExploitResult({"script": script[:200]}, 0, out, {}, ok)
        except subprocess.TimeoutExpired:
            return ExploitResult({"script": script[:200]}, 0, "timeout", {}, False, "timeout")

    def _proc_alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def _logs(self) -> str:
        try:
            return self._log_path.read_text()[-2000:] if self._log_path else ""
        except Exception:
            return ""

    def down(self) -> None:
        self._stop_proc()


# --------------------------------------------------------------------------- #
DOCKERFILE = """FROM {base_image}
WORKDIR /app
COPY . /app
RUN {install_cmd} || true
RUN pip install --no-cache-dir pytest httpx || true
EXPOSE {port}
CMD {run_cmd}
"""


# A constant program, run inside the container, that issues one HTTP request to
# the app on container-localhost. Request fields arrive via env vars (never
# interpolated into the command) so an untrusted PoC cannot inject shell.
_INCONTAINER_HTTP = (
    "import os,json,httpx\n"
    "m=os.environ['PP_METHOD'];u=os.environ['PP_URL']\n"
    "h=json.loads(os.environ.get('PP_HEADERS') or '{}')\n"
    "b=os.environ.get('PP_BODY') or None\n"
    "try:\n"
    "    r=httpx.request(m,u,headers=h,content=b,timeout=10,follow_redirects=True)\n"
    "    print('PPJSON'+json.dumps({'status':r.status_code,'body':r.text,'headers':dict(r.headers)}))\n"
    "except Exception as e:\n"
    "    print('PPJSON'+json.dumps({'status':0,'body':str(e),'headers':{}}))\n"
)


@dataclass
class DockerRunner(_Base):
    """Isolated container runner. No host port is published and the network is
    `none`: the app is unreachable from the host and cannot egress. PoCs run
    inside the container against container-localhost."""

    image: str = field(default="", init=False)
    name: str = field(default="", init=False)

    def __post_init__(self) -> None:
        super().__post_init__()
        self.image = f"patchproof-img-{uuid.uuid4().hex[:8]}"
        self.name = f"patchproof-{uuid.uuid4().hex[:8]}"

    @property
    def _internal_base(self) -> str:
        return f"http://127.0.0.1:{self.spec.port}"

    @property
    def base_url(self) -> str:  # for display only
        return f"{self._internal_base} (in container {self.name})"

    def up(self) -> None:
        if not docker_available():
            raise RuntimeError("docker is not available")
        self._build()
        self._run_container()
        self._wait_ready()

    def _wait_ready(self, timeout: float = 60.0) -> None:
        deadline = time.time() + timeout
        last = ""
        while time.time() < deadline:
            if not self._proc_alive():
                raise RuntimeError(f"container exited early:\n{self._logs()}")
            probe = (f"import httpx,sys;sys.exit(0 if httpx.get('{self._internal_base}',"
                     "timeout=2).status_code<500 else 1)")
            r = subprocess.run(
                ["docker", "exec", self.name, "python", "-c", probe],
                capture_output=True, text=True)
            if r.returncode == 0:
                return
            last = (r.stderr or r.stdout)[-200:]
            time.sleep(0.5)
        raise RuntimeError(f"app did not become ready in {timeout}s: {last}\n{self._logs()}")

    def run_poc(self, poc: PoC) -> ExploitResult:
        if poc.kind == "python":
            return self._run_python_poc(poc)
        return self._exec_http(poc)

    def _exec_http(self, poc: PoC) -> ExploitResult:
        url = poc._abs_url(self._internal_base)
        import json as _json
        env_flags = [
            "-e", f"PP_METHOD={poc.payload.get('method','GET').upper()}",
            "-e", f"PP_URL={url}",
            "-e", f"PP_HEADERS={_json.dumps(poc.payload.get('headers',{}))}",
        ]
        if poc.payload.get("body"):
            env_flags += ["-e", f"PP_BODY={poc.payload['body']}"]
        proc = subprocess.run(
            ["docker", "exec", *env_flags, self.name, "python", "-c", _INCONTAINER_HTTP],
            capture_output=True, text=True, timeout=30)
        out = proc.stdout
        marker = out.rfind("PPJSON")
        if marker < 0:
            return ExploitResult({"url": url}, 0, proc.stderr[-500:], {}, False, "exec_error")
        data = _json.loads(out[marker + len("PPJSON"):].splitlines()[0])
        succeeded = poc.oracle.judge(data["status"], data["body"])
        return ExploitResult(
            {"method": poc.payload.get("method", "GET"), "url": url},
            data["status"], data["body"], data.get("headers", {}), succeeded)

    def _build(self) -> None:
        run_cmd = self.spec.container_run_cmd(self.spec.port)
        inst = self.spec.install_cmd if self.spec.runtime == "python" and (self.workdir / "requirements.txt").exists() else (
            self.spec.install_cmd if self.spec.runtime == "node" else "true"
        )
        dockerfile = DOCKERFILE.format(
            base_image=self.spec.base_image, install_cmd=inst,
            port=self.spec.port, run_cmd=run_cmd,
        )
        (self.workdir / "Dockerfile.patchproof").write_text(dockerfile)
        subprocess.run(
            ["docker", "build", "-q", "-f", "Dockerfile.patchproof", "-t", self.image, "."],
            cwd=str(self.workdir), check=True, capture_output=True,
        )

    def _run_container(self) -> None:
        # No published port, no network: app is not reachable from the host and
        # cannot egress. Working copy is bind-mounted so reloads see patches.
        subprocess.run(
            ["docker", "run", "-d", "--rm", "--name", self.name,
             "--network", "none",
             "-v", f"{self.workdir.resolve()}:/app",
             "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
             self.image],
            check=True, capture_output=True,
        )

    def reload(self) -> None:
        subprocess.run(["docker", "restart", self.name], check=False, capture_output=True)
        self._wait_ready()

    def run_tests(self) -> tuple[bool, str]:
        has_tests = any(self.workdir.rglob("test_*.py")) or any(self.workdir.rglob("*_test.py"))
        if self.spec.runtime == "python" and not has_tests:
            return True, "no tests found (skipped)"
        proc = subprocess.run(
            ["docker", "exec", "-e", f"PATCHPROOF_BASE_URL=http://127.0.0.1:{self.spec.port}",
             self.name, "sh", "-c", self.spec.test_cmd],
            capture_output=True, text=True, timeout=180,
        )
        return proc.returncode == 0, (proc.stdout + proc.stderr)[-4000:]

    def _run_python_poc(self, poc: PoC) -> ExploitResult:
        script = poc.payload.get("script", "")
        proc = subprocess.run(
            ["docker", "exec", "-e", "PATCHPROOF_BASE_URL=http://127.0.0.1:" + str(self.spec.port),
             self.name, "python", "-c", script],
            capture_output=True, text=True, timeout=30,
        )
        out = proc.stdout + proc.stderr
        ok = "EXPLOIT_OK" in out or (("EXPLOIT_FAIL" not in out) and poc.oracle.judge(0, out))
        return ExploitResult({"script": script[:200]}, 0, out, {}, ok)

    def _proc_alive(self) -> bool:
        r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", self.name],
                           capture_output=True, text=True)
        return r.stdout.strip() == "true"

    def _logs(self) -> str:
        r = subprocess.run(["docker", "logs", "--tail", "40", self.name], capture_output=True, text=True)
        return (r.stdout + r.stderr)[-2000:]

    def down(self) -> None:
        subprocess.run(["docker", "rm", "-f", self.name], check=False, capture_output=True)


def make_runner(backend: str, workdir: Path, spec: AppSpec) -> _Base:
    """backend: 'auto' | 'local' | 'docker'."""
    if backend == "auto":
        backend = "docker" if docker_available() else "local"
    if backend == "docker":
        return DockerRunner(workdir=workdir, spec=spec)
    if backend == "local":
        return LocalRunner(workdir=workdir, spec=spec)
    raise ValueError(f"unknown runner backend: {backend}")
