#!/usr/bin/env python3
"""masscan-style fast port sweep MCP server (mock).

Given a subnet (CIDR) and a port list, returns hosts with open ports. Ships a
deterministic mock; scope is still enforced per target by the console.
"""
from __future__ import annotations
import ipaddress, json, os
from mcp.server import MCPServer

srv = MCPServer("redeye-masscan")
_DEFAULT_PORTS = [22, 80, 443, 3389, 8080]


@srv.tool(description="Fast port sweep across a subnet (CIDR). Returns hosts "
                      "with open ports.")
def sweep(subnet: str, ports: str = "") -> str:
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return json.dumps({"vendor": "masscan", "assets": [], "findings": []})
    plist = [int(p) for p in ports.replace(" ", "").split(",") if p.strip().isdigit()] \
        or _DEFAULT_PORTS
    hosts = list(net.hosts())[:16]
    assets = []
    for i, ip in enumerate(hosts):
        openp = [p for j, p in enumerate(plist) if (int(ip) + j) % 3 == 0]
        if not openp:
            continue
        assets.append({"id": str(ip), "label": str(ip), "kind": "host",
                       "ip": str(ip),
                       "ports": [{"port": p, "state": "open", "proto": "tcp",
                                  "service": {22: "ssh", 80: "http", 443: "https",
                                              3389: "rdp", 8080: "http"}.get(p, "")}
                                 for p in openp]})
    return json.dumps({"vendor": "masscan", "mock": True,
                       "assets": assets, "findings": []})


if __name__ == "__main__":
    srv.run("stdio")
