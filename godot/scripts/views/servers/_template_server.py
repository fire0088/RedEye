#!/usr/bin/env python3
"""TEMPLATE: add a new tool integration to REDEYE in ~5 minutes.

Copy this file to servers/<yourtool>_server.py, fill in the tool(s), then add a
block to mcp_config.json pointing at it. That's the whole process -- no changes
to the app itself.

    1. Write @srv.tool functions that shell out to your tool (real) and return
       a --mock payload when the binary is absent. Return JSON as a string.

    2. Choose (or write) an EXTRACTOR to route your JSON onto REDEYE's surfaces.
       Set "extractor" in the config block to one of:
         "nmap" / "roslyn"        -> map nodes (host / endpoint)
         "nuclei" / "wapiti"      -> findings DB (+ nodes, + secrets)
         "secret"                 -> key vault only
         ""                       -> chat only (no routing)
       To add a brand-new routing shape, add one function in
       redeye/extractors.py with @register("<name>") that yields any mix of:
         HostUpsert(id,label,kind,ip,hostname,os,status,ports,meta,color)
         FindingUpsert(dedupe,title,severity,hosts,description,recommendation)
         VaultUpsert(kind,label,username,secret,scope,notes)

    3. Add to mcp_config.json:
         "yourtool": {
           "name": "yourtool", "category": "recon",
           "command": "python3", "args": ["servers/yourtool_server.py"],
           "env": {}, "color": [120, 200, 255],
           "extractor": "secret", "enabled": true
         }

The JSON shapes the built-in extractors understand:

  # "secret" extractor -- push credentials/secrets to the vault
  {"secrets": [{"kind":"secret","label":"...","secret":"...","scope":"..."}],
   "credentials": [{"username":"admin","password":"...","scope":"10.0.0.5"}]}

  # "nuclei" extractor -- findings (+ optional per-finding "secret")
  {"findings": [{"template_id":"...","name":"...","severity":"high",
                 "host":"...","matched_at":"...","description":"...",
                 "remediation":"...","secret":"optional-extracted-secret"}]}

  # "wapiti" extractor -- web-app vulnerabilities
  {"target":"https://app","vulnerabilities":[{"category":"SQL Injection",
     "level":3,"path":"/x","info":"...","solution":"..."}]}
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

from mcp.server import MCPServer

srv = MCPServer("redeye-yourtool")

BIN = os.environ.get("REDEYE_YOURTOOL_BIN", "yourtool")
FORCE_MOCK = os.environ.get("REDEYE_YOURTOOL_MOCK", "") == "1"


def _have() -> bool:
    return not FORCE_MOCK and shutil.which(BIN) is not None


def _mock(target: str) -> dict:
    # Return whatever your chosen extractor expects. Example: a discovered cred.
    return {
        "tool": "scan", "target": target, "mock": True,
        "credentials": [
            {"username": "svc-backup", "password": "backup!2024",
             "scope": target, "kind": "credential",
             "label": "found in exposed backup config"},
        ],
    }


@srv.tool(description="One-line description of what this tool does. Keep it "
                      "clear -- RED reads it to decide when to call the tool.")
def scan(target: str) -> str:
    if not _have():
        return json.dumps(_mock(target))
    try:
        proc = subprocess.run([BIN, target], capture_output=True, text=True,
                              timeout=600)
        # ... parse proc.stdout into the extractor's JSON shape ...
        return json.dumps({"tool": "scan", "target": target, "mock": False,
                           "credentials": []})
    except Exception as e:  # noqa: BLE001
        return json.dumps({"tool": "scan", "target": target, "error": str(e),
                           "mock": False})


if __name__ == "__main__":
    srv.run("stdio")
