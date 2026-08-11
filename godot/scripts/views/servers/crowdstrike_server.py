#!/usr/bin/env python3
"""CrowdStrike Falcon MCP server for REDEYE.

Pulls managed hosts (Falcon Discover / Hosts API) and vulnerabilities (Falcon
Spotlight) via the Falcon OAuth2 API. Falls back to mock data when API
credentials are absent so the inventory populates without a Falcon tenant.

Results flow through the "crowdstrike" extractor -> hosts become inventory/map
nodes, Spotlight vulns become findings.

Environment:
    FALCON_CLIENT_ID / FALCON_CLIENT_SECRET   API credentials
    FALCON_BASE_URL       API host (default https://api.crowdstrike.com)
    REDEYE_CROWDSTRIKE_MOCK=1                  force mock mode

NOTE: the real API paths follow CrowdStrike's documented endpoints but have not
been run against a live tenant here -- verify on first use.
"""
from __future__ import annotations

import json
import os

from mcp.server import MCPServer

from _apiutil import filter_subnet, http_json, in_subnet, oauth2_token

srv = MCPServer("redeye-crowdstrike")

BASE = os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com").rstrip("/")
CID = os.environ.get("FALCON_CLIENT_ID", "")
CSEC = os.environ.get("FALCON_CLIENT_SECRET", "")
FORCE_MOCK = os.environ.get("REDEYE_CROWDSTRIKE_MOCK", "") == "1"


def _token():
    tok = oauth2_token(f"{BASE}/oauth2/token", CID, CSEC)
    return tok.get("access_token", "")


def _have() -> bool:
    return not FORCE_MOCK and bool(CID and CSEC)


def _auth_headers():
    return {"Authorization": f"Bearer {_token()}", "Accept": "application/json"}


# -- real API ----------------------------------------------------------------
def _hosts(hdr, filt) -> list:
    params = {"limit": 200}
    if filt:
        params["filter"] = filt
    ids = http_json("GET", f"{BASE}/devices/queries/devices/v1",
                    headers=hdr, params=params).get("resources", [])
    if not ids:
        return []
    ent = http_json("POST", f"{BASE}/devices/entities/devices/v2",
                    headers=hdr, data={"ids": ids}).get("resources", [])
    out = []
    for d in ent:
        is_server = str(d.get("product_type_desc", "")).lower() == "server"
        out.append({
            "id": d.get("device_id", ""),
            "kind": "server" if is_server else "host",
            "label": d.get("hostname", d.get("device_id", "")),
            "ip": d.get("local_ip", ""), "hostname": d.get("hostname", ""),
            "os": d.get("os_version", d.get("platform_name", "")),
            "status": d.get("status", ""),
            "meta": {"external_ip": d.get("external_ip", ""),
                     "mac": d.get("mac_address", ""),
                     "platform": d.get("platform_name", ""),
                     "agent": d.get("agent_version", ""),
                     "site": d.get("site_name", "")}})
    return out


def _vulns(hdr, filt, subnet) -> list:
    params = {"limit": 200}
    params["filter"] = filt or "status:'open'"
    ids = http_json("GET", f"{BASE}/spotlight/queries/vulnerabilities/v1",
                    headers=hdr, params=params).get("resources", [])
    if not ids:
        return []
    ent = http_json("POST", f"{BASE}/spotlight/entities/vulnerabilities/v2",
                    headers=hdr, data={"ids": ids}).get("resources", [])
    out = []
    for v in ent:
        cve = (v.get("cve") or {})
        host = (v.get("host_info") or {})
        ip = host.get("local_ip", "")
        if subnet and ip and not in_subnet(ip, subnet):
            continue
        out.append({
            "id": v.get("id", ""), "cve": cve.get("id", ""),
            "title": cve.get("id", "") or "Spotlight vulnerability",
            "severity": cve.get("severity", "MEDIUM"),
            "asset": host.get("hostname", ""), "ip": ip,
            "description": cve.get("description", ""),
            "recommendation": "Apply the vendor patch / remediation for this CVE."})
    return out


# -- mock --------------------------------------------------------------------
def _mock_hosts():
    return [
        {"id": "cs-dev-9f1", "kind": "server", "label": "APP-PROD-01",
         "ip": "10.0.0.11", "hostname": "APP-PROD-01", "os": "Windows Server 2022",
         "status": "normal", "meta": {"external_ip": "54.1.2.3",
         "platform": "Windows", "agent": "7.14", "site": "us-east"}},
        {"id": "cs-dev-3a2", "kind": "host", "label": "LT-ESCHULTZ",
         "ip": "10.0.5.40", "hostname": "LT-ESCHULTZ", "os": "Windows 11",
         "status": "normal", "meta": {"platform": "Windows", "agent": "7.14"}},
    ]


def _mock_vulns(subnet):
    v = [
        {"id": "cs-v-1", "cve": "CVE-2024-21412", "title": "CVE-2024-21412",
         "severity": "HIGH", "asset": "APP-PROD-01", "ip": "10.0.0.11", "remote": True,
         "description": "SmartScreen bypass leading to remote code execution.",
         "recommendation": "Apply February 2024 cumulative update."},
        {"id": "cs-v-2", "cve": "CVE-2023-23397", "title": "CVE-2023-23397",
         "severity": "CRITICAL", "asset": "APP-PROD-01", "ip": "10.0.0.11", "remote": True,
         "description": "Outlook privilege escalation via crafted reminder.",
         "recommendation": "Patch Outlook; block outbound SMB."},
    ]
    return filter_subnet(v, subnet)


# -- tools -------------------------------------------------------------------
@srv.tool(description="List CrowdStrike Falcon managed hosts (servers + "
                      "workstations). `filter` is an optional FQL filter "
                      "(e.g. \"platform_name:'Windows'\"). Populates inventory/map.")
def list_hosts(filter: str = "") -> str:
    if not _have():
        return json.dumps({"vendor": "crowdstrike", "mock": True,
                           "assets": _mock_hosts(), "findings": []})
    try:
        hdr = _auth_headers()
        return json.dumps({"vendor": "crowdstrike", "mock": False,
                           "assets": _hosts(hdr, filter), "findings": []})
    except Exception as e:  # noqa: BLE001
        return json.dumps({"vendor": "crowdstrike", "mock": False, "error": str(e),
                           "assets": [], "findings": []})


@srv.tool(description="List CrowdStrike Falcon Spotlight vulnerabilities. "
                      "`subnet` (CIDR) filters to hosts in that range -- use for "
                      "'find vulns in this subnet'. `filter` is optional FQL. "
                      "Writes to the findings DB.")
def list_vulns(filter: str = "", subnet: str = "") -> str:
    if not _have():
        return json.dumps({"vendor": "crowdstrike", "mock": True,
                           "assets": [], "findings": _mock_vulns(subnet)})
    try:
        hdr = _auth_headers()
        return json.dumps({"vendor": "crowdstrike", "mock": False,
                           "assets": [], "findings": _vulns(hdr, filter, subnet)})
    except Exception as e:  # noqa: BLE001
        return json.dumps({"vendor": "crowdstrike", "mock": False, "error": str(e),
                           "assets": [], "findings": []})


if __name__ == "__main__":
    srv.run("stdio")
