#!/usr/bin/env python3
"""wapiti MCP server for REDEYE.

Wraps the `wapiti` web-application vulnerability scanner. Uses the real binary
when present (running a JSON report and parsing it); otherwise returns
clearly-flagged mock vulnerabilities. Results flow through the "wapiti"
extractor into the findings database (deduped) and add a host node to the map.

Environment:
    REDEYE_WAPITI_MOCK=1   force mock mode
    REDEYE_WAPITI_BIN      path to wapiti (default: "wapiti")

SAFETY: only scan applications you are authorised to test.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile

from mcp.server import MCPServer

srv = MCPServer("redeye-wapiti")

BIN = os.environ.get("REDEYE_WAPITI_BIN", "wapiti")
FORCE_MOCK = os.environ.get("REDEYE_WAPITI_MOCK", "") == "1"

# wapiti report level (1..) -> our severity words
_LEVEL = {1: "low", 2: "medium", 3: "high", 4: "critical"}


def _have() -> bool:
    return not FORCE_MOCK and shutil.which(BIN) is not None


def _run(url: str, scope: str) -> dict:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out = tf.name
    try:
        subprocess.run([BIN, "-u", url, "--scope", scope or "folder",
                        "-f", "json", "-o", out],
                       capture_output=True, text=True, timeout=1800)
        with open(out, "r", encoding="utf-8") as f:
            report = json.load(f)
    finally:
        try:
            os.unlink(out)
        except OSError:
            pass
    vulns = []
    for cat, entries in (report.get("vulnerabilities") or {}).items():
        for e in entries:
            vulns.append({
                "category": cat,
                "level": e.get("level", 2),
                "path": e.get("path", ""),
                "info": e.get("info", ""),
                "solution": e.get("solution", ""),
            })
    return {"tool": "scan", "target": url, "mock": False, "vulnerabilities": vulns}


def _mock(url: str) -> dict:
    return {
        "tool": "scan", "target": url, "mock": True,
        "vulnerabilities": [
            {"category": "SQL Injection", "level": 3, "path": "/search?q=",
             "info": "Injectable 'q' parameter on the search endpoint.",
             "solution": "Use parameterised queries / prepared statements."},
            {"category": "Cross Site Scripting", "level": 2,
             "path": "/comment", "info": "Reflected XSS in the comment field.",
             "solution": "Contextually output-encode user input."},
            {"category": "Cross Site Request Forgery", "level": 2,
             "path": "/account/email",
             "info": "State-changing POST lacks an anti-CSRF token.",
             "solution": "Add and validate per-request CSRF tokens."},
        ],
    }


@srv.tool(description="Run wapiti against a target web-app URL. scope is one of "
                      "page|folder|domain|url (default folder). Reported "
                      "vulnerabilities are written to the findings database.")
def scan(target: str, scope: str = "folder") -> str:
    if not _have():
        return json.dumps(_mock(target))
    try:
        return json.dumps(_run(target, scope))
    except Exception as e:  # noqa: BLE001
        return json.dumps({"tool": "scan", "target": target, "error": str(e),
                           "mock": False, "vulnerabilities": []})


if __name__ == "__main__":
    srv.run("stdio")
