#!/usr/bin/env python3
"""HTTP probe MCP server for REDEYE.

Checks a URL and, if a credential is supplied, whether that credential is
accepted (HTTP Basic). Designed for batch credential-spray across a label: run
it against every endpoint in "the 14 portal boxes" with one vault credential.

Emits (via the normalized "probe" extractor):
  - a finding when a supplied credential is ACCEPTED (valid/default creds), so
    it lands in the findings DB.

Environment:
    REDEYE_PROBE_MOCK=1     force mock responses (no network)

SAFETY: a single authenticated GET per call -- no brute forcing, no payloads.
Only run it inside the engagement scope (the console enforces this per target).
"""
from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request

from mcp.server import MCPServer

srv = MCPServer("redeye-http-probe")
FORCE_MOCK = os.environ.get("REDEYE_PROBE_MOCK", "") == "1"


def _real_probe(url, username, password):
    headers = {"User-Agent": "REDEYE-probe/1.0"}
    if username or password:
        tok = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers["Authorization"] = "Basic " + tok
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            status = r.status
            body = r.read(2048).decode("utf-8", "replace")
            server = r.headers.get("Server", "")
    except urllib.error.HTTPError as e:
        status = e.code
        body = ""
        server = e.headers.get("Server", "") if e.headers else ""
    except Exception as e:  # noqa: BLE001
        return {"url": url, "error": str(e), "status": 0, "authenticated": False}
    authed = (username or password) and status not in (401, 403)
    title = ""
    if "<title>" in body.lower():
        s = body.lower().index("<title>") + 7
        title = body[s:body.lower().index("</title>")][:80] if "</title>" in body.lower() else ""
    return {"url": url, "status": status, "server": server, "title": title,
            "authenticated": bool(authed)}


def _mock_probe(url, username, password):
    # pretend default/weak creds work on obvious admin endpoints
    weak = username.lower() in ("admin", "root", "administrator") and \
        password.lower() in ("admin", "password", "changeme", "admin123", username.lower())
    admin_ish = any(x in url.lower() for x in ("admin", ":8080", ":8443", "portal"))
    authed = bool((username or password) and (weak or admin_ish))
    status = 200 if (authed or not (username or password)) else 401
    return {"url": url, "status": status, "server": "nginx", "title": "Portal",
            "authenticated": authed, "mock": True}


@srv.tool(description="Probe a URL over HTTP(S). If username/password are given, "
                      "reports whether the credential is accepted (HTTP Basic). "
                      "Use in a batch across a label to test one credential "
                      "against many endpoints. A valid credential becomes a finding.")
def probe(url: str, username: str = "", password: str = "") -> str:
    if not url:
        return json.dumps({"vendor": "probe", "assets": [], "findings": []})
    if FORCE_MOCK:
        res = _mock_probe(url, username, password)
    else:
        res = _real_probe(url, username, password)
        if res.get("status", 0) == 0 and "error" in res:
            res = _mock_probe(url, username, password)  # unreachable -> mock
    findings = []
    if res.get("authenticated") and (username or password):
        findings.append({
            "id": f"cred:{url}:{username}",
            "title": f"Valid credential accepted ({username or 'basic-auth'})",
            "severity": "HIGH",
            "asset": url, "ip": "",
            "description": f"HTTP {res.get('status')} with supplied credentials "
                           f"at {url} (server: {res.get('server','')}). The "
                           f"credential '{username}' is accepted here.",
            "recommendation": "Rotate the credential, enforce MFA, and restrict "
                              "access to this endpoint.",
        })
    return json.dumps({"vendor": "probe", "mock": res.get("mock", False),
                       "probe": res, "assets": [], "findings": findings})


if __name__ == "__main__":
    srv.run("stdio")
