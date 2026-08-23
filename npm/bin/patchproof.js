#!/usr/bin/env node
/**
 * PatchProof npm launcher.
 *
 * Ensures Python + the `patchproof-repro` PyPI package are available, then
 * forwards all arguments to the `patchproof` CLI.
 *
 * Env overrides:
 *   PATCHPROOF_PYTHON   python executable to use (default: auto-detect)
 *   PATCHPROOF_SKIP_INSTALL=1   never auto-pip-install (fail fast instead)
 */
"use strict";

const { spawnSync } = require("child_process");
const os = require("os");
const path = require("path");

const PYPI_PACKAGE = "patchproof-repro";
const MIN_PY = [3, 11];

function candidates() {
  if (process.env.PATCHPROOF_PYTHON) return [process.env.PATCHPROOF_PYTHON];
  const list = [];
  if (process.platform === "win32") {
    for (let minor = 13; minor >= 11; minor--) {
      list.push(`C:\\Python3${minor}\\python.exe`);
      list.push(`${os.homedir()}\\AppData\\Local\\Programs\\Python\\Python3${minor}\\python.exe`);
    }
    list.push("py", "python3", "python");
  } else {
    list.push("python3", "python");
  }
  return list;
}

function run(cmd, args) {
  try {
    return spawnSync(cmd, args, { encoding: "utf8" });
  } catch (_) {
    return null;
  }
}

function pyVersionOk(bin) {
  const r = run(bin, ["-c", "import sys;print('%d.%d'%sys.version_info[:2])"]);
  if (!r || r.status !== 0) return false;
  const [maj, min] = String(r.stdout).trim().split(".").map(Number);
  return maj > MIN_PY[0] || (maj === MIN_PY[0] && min >= MIN_PY[1]);
}

function patchproofInstalled(bin) {
  const probe =
    process.platform === "win32" && /py(\.exe)?$/i.test(bin)
      ? ["-3", "-c", "import patchproof; print('ok')"]
      : ["-c", "import patchproof; print('ok')"];
  const r = run(bin, probe);
  return !!r && r.status === 0 && String(r.stdout).includes("ok");
}

function install(bin) {
  if (process.env.PATCHPROOF_SKIP_INSTALL === "1") {
    console.error(
      `[patchproof] ${PYPI_PACKAGE} is not installed in the current environment.\n` +
        `             Install it with: pip install ${PYPI_PACKAGE}`
    );
    process.exit(2);
  }
  console.error(`[patchproof] Installing Python package ${PYPI_PACKAGE} ...`);
  const r = run(bin, [
    "-m",
    "pip",
    "install",
    "--user",
    "--quiet",
    "--disable-pip-version-check",
    PYPI_PACKAGE,
  ]);
  if (!r || r.status !== 0) {
    console.error(`[patchproof] pip install failed. Try manually: pip install ${PYPI_PACKAGE}`);
    if (r && r.stderr) console.error(r.stderr);
    process.exit(1);
  }
}

(function main() {
  let python = null;
  for (const cand of candidates()) {
    if (pyVersionOk(cand)) {
      python = cand;
      break;
    }
  }
  if (!python) {
    console.error(
      "[patchproof] No Python >= 3.11 found on PATH.\n" +
        "             Install from https://www.python.org/downloads/ and retry."
    );
    process.exit(1);
  }

  if (!patchproofInstalled(python)) install(python);

  // Re-exec the real CLI, forwarding argv.
  const cliArgs = process.argv.slice(2);
  const execArgs =
    process.platform === "win32" && /py(\.exe)?$/i.test(python)
      ? ["-3", "-m", "patchproof.cli", ...cliArgs]
      : ["-m", "patchproof.cli", ...cliArgs];

  const result = spawnSync(python, execArgs, { stdio: "inherit" });
  process.exit(result.status ?? 1);
})();
