#!/usr/bin/env python3
"""Tenable.io MCP server for REDEYE.

Pulls assets and vulnerabilities from Tenable.io (Tenable Vulnerability
Management) via its REST API. Falls back to mock data when API keys are absent.

Results flow through the "tenable" extractor -> assets become inventory/map
nodes, vulnerabilities become findings.

Environment:
    TENABLE_ACCESS_KEY / TENABLE_SECRET_KEY   API keys
    TENABLE_BASE_URL      API host (default https://cloud.tenable.com)
    REDEYE_TENABLE_MOCK=1                      force mock mode

NOTE: real API paths follow Tenable's documented endpoints but have not been run
against a live tenant here -- verify on first use.
"""
from __future__ import annotations

import json
import os

from mcp.server import MCPServer

from _apiutil import filter_subnet, http_json, in_subnet

srv = MCPServer("redeye-tenable")

BASE = os.environ.get("TENABLE_BASE_URL", "https://cloud.tenable.com").rstrip("/")
AK = os.environ.get("TENABLE_ACCESS_KEY", "")
SK = os.environ.get("TENABLE_SECRET_KEY", "")
FORCE_MOCK = os.environ.get("REDEYE_TENABLE_MOCK", "") == "1"

_SEV_NAME = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}


def _have() -> bool:
    return not FORCE_MOCK and bool(AK and SK)


def _headers():
    return {"X-ApiKeys": f"accessKey={AK};secretKey={SK}",
            "Accept": "application/json"}


# -- real API ----------------------------------------------------------------
def _assets(hdr, subnet) -> list:
    data = http_json("GET", f"{BASE}/assets", headers=hdr)
    out = []
    for a in data.get("assets", []):
        ip = (a.get("ipv4") or [""])[0]
        if subnet and ip and not in_subnet(ip, subnet):
            continue
        os_list = a.get("operating_system") or []
        out.append({
            "id": a.get("id", ""), "kind": "host",
            "label": (a.get("fqdn") or a.get("ipv4") or ["asset"])[0],
            "ip": ip, "hostname": (a.get("fqdn") or [""])[0],
            "os": os_list[0] if os_list else "",
            "status": "up",
            "meta": {"ipv4": a.get("ipv4", []), "mac": a.get("mac_address", []),
                     "sources": [s.get("name") for s in a.get("sources", [])],
                     "tags": a.get("tags", [])}})
    return out


def _vulns(hdr, subnet, severity) -> list:
    # workbench vulnerabilities; then attach affected assets in-subnet
    params = {"date_range": 90}
    if severity:
        # tenable severity filter uses numeric levels
        params["filter.0.filter"] = "severity"
        params["filter.0.quality"] = "eq"
        params["filter.0.value"] = severity
    vulns = http_json("GET", f"{BASE}/workbenches/vulnerabilities",
                      headers=hdr, params=params).get("vulnerabilities", [])
    out = []
    for v in vulns:
        plugin = v.get("plugin_id", "")
        # pull the affected assets for this plugin to get IPs / subnet filter
        assets = http_json(
            "GET", f"{BASE}/workbenches/vulnerabilities/{plugin}/outputs",
            headers=hdr).get("outputs", [])
        ips = []
        for o in assets:
            for st in o.get("states", []):
                for res in st.get("results", []):
                    for ag in res.get("application_protocol", []) if False else []:
                        pass
                    for host in res.get("assets", []):
                        ip = host.get("hostname", "")
                        if ip:
                            ips.append(ip)
        in_scope = [ip for ip in ips if in_subnet(ip, subnet)] if subnet else ips
        if subnet and not in_scope:
            continue
        out.append({
            "id": str(plugin), "cve": (v.get("cves") or [""])[0] if v.get("cves") else "",
            "title": v.get("plugin_name", ""),
            "severity": _SEV_NAME.get(v.get("severity", 2), "MEDIUM"),
            "asset": (in_scope[0] if in_scope else ""), "ip": (in_scope[0] if in_scope else ""),
            "description": v.get("synopsis", ""),
            "recommendation": v.get("solution", "")})
    return out


# -- mock --------------------------------------------------------------------
def _mock_assets(subnet):
    a = [
        {"id": "tn-a1", "kind": "server", "label": "web-prod-01.corp",
         "ip": "10.0.0.11", "hostname": "web-prod-01.corp", "os": "Amazon Linux 2023",
         "status": "up", "meta": {"sources": ["NESSUS_AGENT"]}},
        {"id": "tn-a2", "kind": "network_device", "label": "core-sw-1",
         "ip": "10.0.0.2", "hostname": "core-sw-1", "os": "Cisco IOS",
         "status": "up", "meta": {"sources": ["NESSUS_SCAN"]}},
        {"id": "tn-a3", "kind": "host", "label": "db-prod-01.corp",
         "ip": "10.0.1.22", "hostname": "db-prod-01.corp", "os": "Ubuntu 22.04",
         "status": "up", "meta": {}},
    ]
    return filter_subnet(a, subnet)


def _mock_vulns(subnet):
    v = [
        {"id": "42873", "cve": "CVE-2014-0224", "title": "SSL/TLS MITM (CCS Injection)",
         "severity": "HIGH", "asset": "web-prod-01.corp", "ip": "10.0.0.11",
         "remote": True, "description": "OpenSSL CCS injection permits MITM.",
         "recommendation": "Upgrade OpenSSL to a fixed version."},
        {"id": "104743", "cve": "CVE-2016-2183", "title": "SWEET32 (3DES) birthday attack",
         "severity": "MEDIUM", "asset": "core-sw-1", "ip": "10.0.0.2",
         "remote": True, "description": "3DES cipher suites enabled on the device.",
         "recommendation": "Disable 3DES/legacy cipher suites."},
        {"id": "153953", "cve": "CVE-2021-3156", "title": "Sudo Baron Samedit",
         "severity": "HIGH", "asset": "db-prod-01.corp", "ip": "10.0.1.22",
         "remote": False, "description": "Local privilege escalation in sudo.",
         "recommendation": "Update sudo package."},
    ]
    return filter_subnet(v, subnet)


# -- tools -------------------------------------------------------------------
@srv.tool(description="List Tenable.io assets (hosts, servers, network devices). "
                      "`subnet` (CIDR) filters to that range. Populates inventory/map.")
def list_assets(subnet: str = "") -> str:
    if not _have():
        return json.dumps({"vendor": "tenable", "mock": True,
                           "assets": _mock_assets(subnet), "findings": []})
    try:
        return json.dumps({"vendor": "tenable", "mock": False,
                           "assets": _assets(_headers(), subnet), "findings": []})
    except Exception as e:  # noqa: BLE001
        return json.dumps({"vendor": "tenable", "mock": False, "error": str(e),
                           "assets": [], "findings": []})


@srv.tool(description="List Tenable.io vulnerabilities. `subnet` (CIDR) filters "
                      "to hosts in that range -- use for 'find vulns in this "
                      "subnet'. `severity` optionally filters (info|low|medium|"
                      "high|critical). Writes to the findings DB.")
def list_vulns(subnet: str = "", severity: str = "") -> str:
    if not _have():
        return json.dumps({"vendor": "tenable", "mock": True, "assets": [],
                           "findings": _mock_vulns(subnet)})
    try:
        return json.dumps({"vendor": "tenable", "mock": False, "assets": [],
                           "findings": _vulns(_headers(), subnet, severity)})
    except Exception as e:  # noqa: BLE001
        return json.dumps({"vendor": "tenable", "mock": False, "error": str(e),
                           "assets": [], "findings": []})


if __name__ == "__main__":
    srv.run("stdio")
