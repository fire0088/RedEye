#!/usr/bin/env python3
"""httpx-style web fingerprinting MCP server for REDEYE.

Given a URL (or host:port), reports status/title/server and a coarse tech guess,
and upserts the asset with a detected web service so auto-label groups by the
real app. Best-effort real probe via urllib; mock fallback.
    REDEYE_HTTPX_MOCK=1   force mock
"""
from __future__ import annotations
import json, os, re, urllib.request
from urllib.parse import urlparse
from mcp.server import MCPServer

srv = MCPServer("redeye-httpx")
MOCK = os.environ.get("REDEYE_HTTPX_MOCK", "") == "1"
_TECH = [("nginx", "nginx"), ("apache", "apache"), ("iis", "iis"),
         ("tomcat", "tomcat"), ("express", "node"), ("werkzeug", "flask"),
         ("gunicorn", "python"), ("cloudflare", "cloudflare")]


def _guess(server, body):
    blob = f"{server} {body}".lower()
    for hint, fam in _TECH:
        if hint in blob:
            return fam
    return ""


def _real(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "REDEYE-httpx/1.0"})
        with urllib.request.urlopen(req, timeout=12) as r:
            body = r.read(4096).decode("utf-8", "replace")
            server = r.headers.get("Server", "")
            status = r.status
    except Exception as e:  # noqa: BLE001
        return None
    title = ""
    m = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
    if m:
        title = m.group(1).strip()[:80]
    return {"status": status, "server": server, "title": title,
            "tech": _guess(server, body)}


def _mock(url):
    p = urlparse(url)
    fam = "nginx" if (p.port in (443, 8443) or p.scheme == "https") else "apache"
    ver = {"nginx": "1.24.0", "apache": "2.4.58"}[fam]
    return {"status": 200, "server": f"{fam}/{ver}", "title": "Portal",
            "tech": fam, "version": ver, "mock": True}


@srv.tool(description="Fingerprint a web endpoint (status, title, server, tech). "
                      "Upserts the asset with the detected web service so labels "
                      "group by the real application.")
def fingerprint(url: str) -> str:
    if not url:
        return json.dumps({"vendor": "httpx", "assets": [], "findings": []})
    if "://" not in url:
        url = "http://" + url
    res = _real(url) if not MOCK else None
    if res is None:
        res = _mock(url)
    p = urlparse(url)
    host = p.hostname or url
    port = p.port or (443 if p.scheme == "https" else 80)
    svc = (res.get("tech") or p.scheme or "http")
    ver = res.get("version", "")
    svc_str = f"{p.scheme}/{svc}".strip("/")
    if ver:
        svc_str += " " + ver
    asset = {"id": host, "label": host, "kind": "host", "hostname": host,
             "ports": [{"port": port, "state": "open",
                        "service": svc_str, "proto": "tcp"}],
             "meta": {"title": res.get("title", ""), "tech": res.get("tech", ""),
                      "version": ver, "http_status": res.get("status", "")}}
    return json.dumps({"vendor": "httpx", "mock": res.get("mock", False),
                       "assets": [asset], "findings": []})


if __name__ == "__main__":
    srv.run("stdio")
