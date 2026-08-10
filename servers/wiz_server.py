#!/usr/bin/env python3
"""Wiz MCP server for REDEYE.

Pulls cloud resources (VMs, containers, serverless, etc.) and vulnerability
findings from Wiz via its GraphQL API (OAuth2 client-credentials). Falls back to
mock data when credentials are absent.

Results flow through the "wiz" extractor -> resources become inventory/map
nodes (coloured by kind), vuln findings become findings.

Environment:
    WIZ_CLIENT_ID / WIZ_CLIENT_SECRET   service-account credentials
    WIZ_AUTH_URL     token endpoint (default https://auth.app.wiz.io/oauth/token)
    WIZ_API_URL      tenant GraphQL endpoint (e.g. https://api.us1.app.wiz.io/graphql)
    REDEYE_WIZ_MOCK=1                    force mock mode

NOTE: real GraphQL follows Wiz's documented schema but has not been run against a
live tenant here -- verify on first use.
"""
from __future__ import annotations

import json
import os

from mcp.server import MCPServer

from _apiutil import filter_subnet, http_json, in_subnet, oauth2_token

srv = MCPServer("redeye-wiz")

AUTH_URL = os.environ.get("WIZ_AUTH_URL", "https://auth.app.wiz.io/oauth/token")
API_URL = os.environ.get("WIZ_API_URL", "")
CID = os.environ.get("WIZ_CLIENT_ID", "")
CSEC = os.environ.get("WIZ_CLIENT_SECRET", "")
FORCE_MOCK = os.environ.get("REDEYE_WIZ_MOCK", "") == "1"

# Wiz nativeType/type -> our inventory kind
_KIND = {
    "VIRTUAL_MACHINE": "server", "VIRTUAL_MACHINE_IMAGE": "cloud_resource",
    "CONTAINER": "container", "CONTAINER_IMAGE": "container",
    "POD": "container", "KUBERNETES_CLUSTER": "container",
    "SERVERLESS": "lambda", "LAMBDA": "lambda", "FUNCTION": "lambda",
    "LOAD_BALANCER": "network_device", "GATEWAY": "network_device",
    "VIRTUAL_NETWORK": "network_device", "SUBNET": "network_device",
    "DATABASE": "database", "DB_SERVER": "database", "BUCKET": "cloud_resource",
}

_RES_QUERY = """
query CloudResources($first:Int,$after:String){
  cloudResources(first:$first, after:$after){
    nodes{ id name type subscriptionId region
      graphEntity{ properties } }
    pageInfo{ hasNextPage endCursor }
  }
}"""

_VULN_QUERY = """
query Vulns($first:Int){
  vulnerabilityFindings(first:$first){
    nodes{ id name CVEDescription severity
      vulnerableAsset{ ... on VulnerableAssetBase { name providerUniqueId } }
      cvssSeverity ipAddresses portalUrl remediation }
  }
}"""


def _have() -> bool:
    return not FORCE_MOCK and bool(CID and CSEC and API_URL)


def _headers():
    tok = oauth2_token(AUTH_URL, CID, CSEC, extra={"audience": "wiz-api"})
    return {"Authorization": f"Bearer {tok.get('access_token','')}",
            "Content-Type": "application/json"}


def _gql(hdr, query, variables):
    return http_json("POST", API_URL, headers=hdr,
                     data={"query": query, "variables": variables})


# -- real API ----------------------------------------------------------------
def _resources(hdr, subnet) -> list:
    out = []
    data = _gql(hdr, _RES_QUERY, {"first": 200})
    nodes = (((data.get("data") or {}).get("cloudResources") or {}).get("nodes")) or []
    for n in nodes:
        props = (n.get("graphEntity") or {}).get("properties") or {}
        ip = props.get("ipAddress") or props.get("privateIp") or ""
        if subnet and ip and not in_subnet(ip, subnet):
            continue
        out.append({
            "id": n.get("id", ""),
            "kind": _KIND.get(str(n.get("type", "")).upper(), "cloud_resource"),
            "label": n.get("name", ""), "ip": ip,
            "region": n.get("region", ""), "account": n.get("subscriptionId", ""),
            "status": props.get("status", ""),
            "meta": {"type": n.get("type", ""),
                     "cloud": props.get("cloudPlatform", "")}})
    return out


def _vulns(hdr, subnet) -> list:
    out = []
    data = _gql(hdr, _VULN_QUERY, {"first": 200})
    nodes = (((data.get("data") or {}).get("vulnerabilityFindings") or {}).get("nodes")) or []
    for v in nodes:
        asset = v.get("vulnerableAsset") or {}
        ips = v.get("ipAddresses") or []
        ip = ips[0] if ips else ""
        if subnet and ip and not in_subnet(ip, subnet):
            continue
        out.append({
            "id": v.get("id", ""), "cve": v.get("name", ""),
            "title": v.get("name", ""),
            "severity": v.get("severity", v.get("cvssSeverity", "MEDIUM")),
            "asset": asset.get("name", ""), "ip": ip,
            "description": v.get("CVEDescription", ""),
            "recommendation": v.get("remediation", "") or "Remediate per Wiz guidance."})
    return out


# -- mock --------------------------------------------------------------------
def _mock_resources(subnet):
    r = [
        {"id": "wiz-vm-1", "kind": "server", "label": "web-prod-01",
         "ip": "10.0.0.11", "region": "us-east-1", "account": "123456789012",
         "status": "running", "meta": {"type": "VIRTUAL_MACHINE", "cloud": "AWS"}},
        {"id": "wiz-ctr-1", "kind": "container", "label": "api@prod",
         "ip": "10.0.2.30", "region": "us-east-1", "account": "123456789012",
         "status": "running", "meta": {"type": "CONTAINER", "cloud": "AWS"}},
        {"id": "wiz-fn-1", "kind": "lambda", "label": "checkout-fn",
         "region": "us-east-1", "account": "123456789012", "status": "active",
         "meta": {"type": "SERVERLESS", "cloud": "AWS"}},
        {"id": "wiz-db-1", "kind": "database", "label": "orders-rds",
         "ip": "10.0.1.50", "region": "us-east-1", "account": "123456789012",
         "status": "available", "meta": {"type": "DB_SERVER", "cloud": "AWS"}},
    ]
    return filter_subnet(r, subnet)


def _mock_vulns(subnet):
    v = [
        {"id": "wiz-v-1", "cve": "CVE-2024-3094", "title": "CVE-2024-3094",
         "severity": "CRITICAL", "asset": "web-prod-01", "ip": "10.0.0.11", "remote": True,
         "description": "xz-utils backdoor reachable via SSH.",
         "recommendation": "Replace liblzma/xz with a clean build."},
        {"id": "wiz-v-2", "cve": "CVE-2023-4911", "title": "CVE-2023-4911 (Looney Tunables)",
         "severity": "HIGH", "asset": "api@prod", "ip": "10.0.2.30", "remote": False,
         "description": "glibc ld.so buffer overflow -> local root.",
         "recommendation": "Patch glibc in the base image and redeploy."},
    ]
    return filter_subnet(v, subnet)


# -- tools -------------------------------------------------------------------
@srv.tool(description="List Wiz cloud resources (VMs, containers, serverless, "
                      "databases, network). `subnet` (CIDR) filters to that "
                      "range. Populates the inventory/map.")
def list_resources(subnet: str = "") -> str:
    if not _have():
        return json.dumps({"vendor": "wiz", "mock": True,
                           "assets": _mock_resources(subnet), "findings": []})
    try:
        return json.dumps({"vendor": "wiz", "mock": False,
                           "assets": _resources(_headers(), subnet), "findings": []})
    except Exception as e:  # noqa: BLE001
        return json.dumps({"vendor": "wiz", "mock": False, "error": str(e),
                           "assets": [], "findings": []})


@srv.tool(description="List Wiz vulnerability findings. `subnet` (CIDR) filters "
                      "to assets in that range -- use for 'find vulns in this "
                      "subnet'. Writes to the findings DB.")
def list_vulns(subnet: str = "") -> str:
    if not _have():
        return json.dumps({"vendor": "wiz", "mock": True, "assets": [],
                           "findings": _mock_vulns(subnet)})
    try:
        return json.dumps({"vendor": "wiz", "mock": False, "assets": [],
                           "findings": _vulns(_headers(), subnet)})
    except Exception as e:  # noqa: BLE001
        return json.dumps({"vendor": "wiz", "mock": False, "error": str(e),
                           "assets": [], "findings": []})


if __name__ == "__main__":
    srv.run("stdio")
