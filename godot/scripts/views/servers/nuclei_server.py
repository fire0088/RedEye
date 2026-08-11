#!/usr/bin/env python3
"""nuclei MCP server for REDEYE.

Wraps the `nuclei` vulnerability scanner. Uses the real binary when present
(parsing its JSONL output); otherwise returns clearly-flagged mock findings so
the findings DB and map populate without nuclei installed.

Its results flow through the "nuclei" extractor: each finding becomes a row in
the findings database (deduped), each host becomes a map node, and any secret a
template extracts is pushed into the key vault.

Environment:
    REDEYE_NUCLEI_MOCK=1   force mock mode
    REDEYE_NUCLEI_BIN      path to nuclei (default: "nuclei")

SAFETY: only scan assets you are authorised to test.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

from mcp.server import MCPServer

srv = MCPServer("redeye-nuclei")

BIN = os.environ.get("REDEYE_NUCLEI_BIN", "nuclei")
FORCE_MOCK = os.environ.get("REDEYE_NUCLEI_MOCK", "") == "1"


def _have() -> bool:
    return not FORCE_MOCK and shutil.which(BIN) is not None


def _run(target: str, severity: str, tags: str) -> list[dict]:
    args = [BIN, "-u", target, "-jsonl", "-silent"]
    if severity:
        args += ["-severity", severity]
    if tags:
        args += ["-tags", tags]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=900)
    findings = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = j.get("info", {})
        findings.append({
            "template_id": j.get("template-id", j.get("templateID", "")),
            "name": info.get("name", ""),
            "severity": info.get("severity", "info"),
            "host": j.get("host", ""),
            "matched_at": j.get("matched-at", j.get("matched", "")),
            "description": info.get("description", ""),
            "remediation": info.get("remediation", ""),
        })
    return findings


def _mock(target: str) -> dict:
    return {
        "tool": "scan", "target": target, "mock": True,
        "findings": [
            {"template_id": "http-missing-security-headers",
             "name": "Missing Security Headers", "severity": "info",
             "host": target, "matched_at": f"{target}/",
             "description": "Response is missing HSTS / CSP headers.",
             "remediation": "Add HSTS and a restrictive Content-Security-Policy."},
            {"template_id": "git-config-exposure",
             "name": "Exposed .git/config", "severity": "medium",
             "host": target, "matched_at": f"{target}/.git/config",
             "description": "The .git directory is served publicly.",
             "remediation": "Block access to the .git directory."},
            {"template_id": "exposed-env-file",
             "name": "Exposed .env file", "severity": "high",
             "host": target, "matched_at": f"{target}/.env",
             "description": "Environment file with credentials is reachable.",
             "remediation": "Remove .env from the web root and rotate secrets.",
             # a secret this template 'extracted' -> lands in the key vault
             "secret": "DB_PASSWORD=s3cr3t-pg-pw"},
        ],
    }


@srv.tool(description="Run nuclei against a target URL/host. severity filters "
                      "(comma list: info,low,medium,high,critical); tags picks "
                      "template groups (e.g. 'cve,exposure'). Findings are "
                      "written to the findings database; discovered secrets go "
                      "to the key vault.")
def scan(target: str, severity: str = "", tags: str = "") -> str:
    if not _have():
        return json.dumps(_mock(target))
    try:
        findings = _run(target, severity, tags)
        return json.dumps({"tool": "scan", "target": target, "mock": False,
                           "findings": findings})
    except Exception as e:  # noqa: BLE001
        return json.dumps({"tool": "scan", "target": target, "error": str(e),
                           "mock": False, "findings": []})


if __name__ == "__main__":
    srv.run("stdio")
