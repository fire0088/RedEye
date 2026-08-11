"""Preflight for the binary-backed scanner tools (nmap / nuclei / wapiti).

For each tool: is its binary installed? If not and auto-install is on, attempt a
best-effort, non-interactive install; then report a status the UI surfaces:

    ok        -> binary present, tool is live
    installed -> was missing, we installed it, now present
    installing-> transient, while an install runs
    mock      -> missing and not installed (couldn't/won't) -> server runs mock
    error     -> an install was attempted and failed

A missing tool is a *soft* warning: the matching MCP server still works in mock
mode, so the app is usable. Installs are best-effort and never interactive --
anything needing admin/sudo simply fails to `error`/`mock` with a helpful hint.
"""
from __future__ import annotations

import platform
import shutil
import subprocess
import sys

INSTALL_TIMEOUT = 240  # seconds, per tool

# tool key -> spec. `server` is the mcp_config server key this binary backs.
TOOLS: dict[str, dict] = {
    "nmap": {
        "name": "nmap", "bin": "nmap", "server": "nmap",
        "install": {
            "Linux": ["apt-get", "install", "-y", "nmap"],
            "Darwin": ["brew", "install", "nmap"],
            "Windows": ["choco", "install", "-y", "nmap"],
        },
        "hint": "Install Nmap from https://nmap.org/download (or `choco install nmap`).",
    },
    "nuclei": {
        "name": "nuclei", "bin": "nuclei", "server": "nuclei",
        "needs": "go",  # go install path; skip if go absent
        "install": {"any": ["go", "install",
                            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"]},
        "hint": "Install nuclei from github.com/projectdiscovery/nuclei/releases.",
    },
    "wapiti": {
        "name": "wapiti", "bin": "wapiti", "server": "wapiti",
        "install": {"any": [sys.executable, "-m", "pip", "install", "--user", "wapiti3"]},
        "hint": "Install with: pip install wapiti3",
    },
}


def _present(bin_name: str) -> bool:
    return shutil.which(bin_name) is not None


def _install_cmd(spec: dict):
    inst = spec.get("install", {})
    return inst.get(platform.system()) or inst.get("any")


def _run(cmd) -> tuple[bool, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=INSTALL_TIMEOUT)
        out = (p.stderr or p.stdout or "").strip()
        return p.returncode == 0, out[-300:]
    except FileNotFoundError:
        return False, f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return False, "install timed out"
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def _report(key: str, status: str, detail: str = "") -> dict:
    spec = TOOLS[key]
    return {"key": spec["server"], "tool": key, "name": spec["name"],
            "status": status, "detail": detail}


def check(key: str) -> dict:
    """Status without attempting any install."""
    spec = TOOLS[key]
    if _present(spec["bin"]):
        return _report(key, "ok")
    return _report(key, "mock", spec.get("hint", ""))


def install(key: str) -> dict:
    """Attempt a best-effort install and return the resulting status."""
    spec = TOOLS[key]
    if _present(spec["bin"]):
        return _report(key, "ok")
    need = spec.get("needs")
    if need and not _present(need):
        return _report(key, "mock", f"needs {need}. " + spec.get("hint", ""))
    cmd = _install_cmd(spec)
    if not cmd:
        return _report(key, "mock", spec.get("hint", ""))
    ok, out = _run(cmd)
    if _present(spec["bin"]):
        return _report(key, "installed", "installed via " + " ".join(cmd[:2]))
    return _report(key, "error",
                   (out or "install failed") + " -- " + spec.get("hint", ""))


def preflight(auto_install: bool = True, keys=None) -> list[dict]:
    """Check every tool; attempt installs for missing ones if auto_install."""
    reports = []
    for k in (keys or list(TOOLS)):
        if _present(TOOLS[k]["bin"]):
            reports.append(_report(k, "ok"))
        elif auto_install:
            reports.append(install(k))
        else:
            reports.append(check(k))
    return reports
