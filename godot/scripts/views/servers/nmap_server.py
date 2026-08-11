#!/usr/bin/env python3
"""nmap MCP server for REDEYE.

Exposes recon tools over MCP. Uses the real `nmap` binary when present (parsing
its XML output); otherwise returns clearly-flagged mock data so the console and
network map stay usable without root/nmap installed.

Environment:
    REDEYE_NMAP_MOCK=1   force mock mode (no real scanning)
    REDEYE_NMAP_BIN      path to nmap (default: "nmap")

Tools:
    ping_sweep(target)                 -> live hosts
    port_scan(target, ports, fast)     -> hosts with open ports/services

SAFETY: only scan hosts you are authorised to test.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET

from mcp.server import MCPServer

srv = MCPServer("redeye-nmap")

NMAP_BIN = os.environ.get("REDEYE_NMAP_BIN", "nmap")
FORCE_MOCK = os.environ.get("REDEYE_NMAP_MOCK", "") == "1"


def _have_nmap() -> bool:
    return not FORCE_MOCK and shutil.which(NMAP_BIN) is not None


def _run_nmap(args: list[str]) -> str:
    proc = subprocess.run(
        [NMAP_BIN, *args, "-oX", "-"],
        capture_output=True, text=True, timeout=300,
    )
    if proc.returncode != 0 and not proc.stdout:
        raise RuntimeError(proc.stderr.strip() or f"nmap exited {proc.returncode}")
    return proc.stdout


def _parse_xml(xml_text: str) -> list[dict]:
    hosts: list[dict] = []
    root = ET.fromstring(xml_text)
    for h in root.findall("host"):
        status = h.find("status")
        state = status.get("state", "unknown") if status is not None else "unknown"
        ip = ""
        for addr in h.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
                break
        hostname = ""
        hn = h.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")
        os_name = ""
        osm = h.find("os/osmatch")
        if osm is not None:
            os_name = osm.get("name", "")
        ports = []
        for p in h.findall("ports/port"):
            st = p.find("state")
            svc = p.find("service")
            ports.append({
                "port": int(p.get("portid", 0)),
                "proto": p.get("protocol", "tcp"),
                "state": st.get("state", "") if st is not None else "",
                "service": svc.get("name", "") if svc is not None else "",
                "version": " ".join(filter(None, [
                    svc.get("product", "") if svc is not None else "",
                    svc.get("version", "") if svc is not None else "",
                ])).strip(),
            })
        hosts.append({"ip": ip, "hostname": hostname, "os": os_name,
                      "status": state, "ports": ports})
    return hosts


# ---------------------------------------------------------------------------
# mock data (used when nmap is unavailable or forced)
# ---------------------------------------------------------------------------
def _mock_ping(target: str) -> dict:
    base = "10.10.0."
    hosts = [{"ip": f"{base}{i}", "hostname": name, "os": "", "status": "up",
              "ports": []}
             for i, name in [(1, "gw.lab"), (5, "web01.lab"), (7, "db01.lab"),
                             (12, "jump.lab"), (23, "build.lab")]]
    return {"tool": "ping_sweep", "target": target, "mock": True, "hosts": hosts}


def _mock_ports(target: str) -> dict:
    hosts = [
        {"ip": "10.10.0.5", "hostname": "web01.lab", "os": "Linux 5.x",
         "status": "up", "ports": [
             {"port": 22, "proto": "tcp", "state": "open", "service": "ssh",
              "version": "OpenSSH 8.9"},
             {"port": 80, "proto": "tcp", "state": "open", "service": "http",
              "version": "nginx 1.24"},
             {"port": 443, "proto": "tcp", "state": "open", "service": "https",
              "version": "nginx 1.24"},
             {"port": 3306, "proto": "tcp", "state": "filtered",
              "service": "mysql", "version": ""}]},
        {"ip": "10.10.0.7", "hostname": "db01.lab", "os": "Linux 5.x",
         "status": "up", "ports": [
             {"port": 5432, "proto": "tcp", "state": "open", "service": "postgresql",
              "version": "PostgreSQL 15"},
             {"port": 6379, "proto": "tcp", "state": "open", "service": "redis",
              "version": "Redis 7.2"}]},
    ]
    return {"tool": "port_scan", "target": target, "mock": True, "hosts": hosts}


# ---------------------------------------------------------------------------
# tools
# ---------------------------------------------------------------------------
@srv.tool(description="Discover live hosts on a target host/CIDR/range via an "
                      "nmap ping sweep (-sn). Returns JSON with a 'hosts' list.")
def ping_sweep(target: str) -> str:
    if not _have_nmap():
        return json.dumps(_mock_ping(target))
    try:
        xml = _run_nmap(["-sn", "-T4", target])
        hosts = [h for h in _parse_xml(xml) if h["status"] == "up"]
        return json.dumps({"tool": "ping_sweep", "target": target,
                           "mock": False, "hosts": hosts})
    except Exception as e:  # noqa: BLE001
        return json.dumps({"tool": "ping_sweep", "target": target,
                           "error": str(e), "mock": False, "hosts": []})


@srv.tool(description="Scan ports on a target host/CIDR and identify services. "
                      "ports: 'top100' | 'top1000' | 'all' | a list like "
                      "'22,80,443' | a range like '1-1024'. fast=True skips "
                      "version detection. Returns JSON with a 'hosts' list "
                      "containing open/filtered ports and services.")
def port_scan(target: str, ports: str = "top100", fast: bool = False) -> str:
    if not _have_nmap():
        return json.dumps(_mock_ports(target))
    args = ["-T4", "-Pn"]
    if ports == "top100":
        args += ["--top-ports", "100"]
    elif ports == "top1000":
        args += ["--top-ports", "1000"]
    elif ports == "all":
        args += ["-p-"]
    else:
        args += ["-p", ports]
    if not fast:
        args += ["-sV", "--version-light"]
    args.append(target)
    try:
        xml = _run_nmap(args)
        hosts = _parse_xml(xml)
        return json.dumps({"tool": "port_scan", "target": target,
                           "mock": False, "hosts": hosts})
    except Exception as e:  # noqa: BLE001
        return json.dumps({"tool": "port_scan", "target": target,
                           "error": str(e), "mock": False, "hosts": []})


if __name__ == "__main__":
    srv.run("stdio")
