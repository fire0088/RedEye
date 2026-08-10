#!/usr/bin/env python3
"""subfinder-style subdomain enumeration MCP server (mock).

Given a domain, returns discovered subdomains as hostname assets. Real subdomain
enumeration needs external data sources; this ships a deterministic mock so the
workflow is usable offline. Swap in a real backend later without touching the
extractor.
"""
from __future__ import annotations
import hashlib, json, os
from mcp.server import MCPServer

srv = MCPServer("redeye-subfinder")
_COMMON = ["www", "api", "dev", "staging", "vpn", "mail", "portal", "admin",
           "git", "jenkins", "grafana", "app"]


@srv.tool(description="Enumerate subdomains of a domain. Returns discovered "
                      "hostnames as assets.")
def subdomains(domain: str) -> str:
    domain = (domain or "").strip().lstrip("*.")
    if not domain:
        return json.dumps({"vendor": "subfinder", "assets": [], "findings": []})
    h = int(hashlib.sha1(domain.encode()).hexdigest(), 16)
    picks = [s for i, s in enumerate(_COMMON) if (h >> i) & 1]
    assets = [{"id": f"{s}.{domain}", "label": f"{s}.{domain}", "kind": "host",
               "hostname": f"{s}.{domain}", "meta": {"discovered_by": "subfinder"}}
              for s in (picks or _COMMON[:3])]
    return json.dumps({"vendor": "subfinder", "mock": True,
                       "assets": assets, "findings": []})


if __name__ == "__main__":
    srv.run("stdio")
