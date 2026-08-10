"""Software component + version inventory.

Aggregates detected software and versions from every source -- nmap service/
version strings, httpx tech + version, and any service banner on an open port --
into a searchable list of components, each with where it was seen (hosts/ports),
which tools reported it, and any findings on the same hosts (so known-vulnerable
builds surface). Pure and testable.
"""
from __future__ import annotations

import json
import re

_VER = re.compile(r"([0-9]+(?:[._][0-9]+)+[a-z0-9._\-]*)", re.I)
_TRAIL = re.compile(r"[ /]([0-9][0-9a-z._\-]*)$", re.I)
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def parse_service(svc: str) -> tuple:
    """('https/nginx 1.24.0') -> ('nginx', '1.24.0'); best-effort."""
    s = str(svc or "").strip()
    if not s:
        return ("", "")
    # drop a scheme prefix like "https/" or "http/"
    head = s.split("/", 1)[0]
    if "/" in s and " " not in head and len(head) <= 6:
        s = s.split("/", 1)[1].strip()
    ver, prod = "", s
    m = _VER.search(s)
    if m:
        ver, prod = m.group(1), s[:m.start()].strip()
    else:
        m2 = _TRAIL.search(s)
        if m2:
            ver, prod = m2.group(1), s[:m2.start()].strip()
    prod = prod.strip(" /-_").lower()
    return (prod, ver)


def _ports(a) -> list:
    try:
        return json.loads(a.get("ports_json") or "[]")
    except Exception:  # noqa: BLE001
        return a.get("ports") or []


def _meta(a) -> dict:
    try:
        return json.loads(a.get("meta_json") or "{}")
    except Exception:  # noqa: BLE001
        return a.get("meta") or {}


def _host_of(a) -> str:
    return str(a.get("label") or a.get("hostname") or a.get("ip") or a.get("id") or "")


def _cve_or_title(t: str) -> str:
    m = _CVE.search(str(t or ""))
    return m.group(0).upper() if m else str(t or "").strip()[:80]


def build_components(assets: list, findings: list) -> list:
    comps = {}

    def add(prod, ver, host, port, src, raw):
        if not prod:
            return
        k = (prod, ver)
        c = comps.setdefault(k, {"product": prod, "version": ver, "hosts": [],
                                 "ports": [], "sources": [], "detections": []})
        if host and host not in c["hosts"]:
            c["hosts"].append(host)
        if port and port not in c["ports"]:
            c["ports"].append(port)
        if src and src not in c["sources"]:
            c["sources"].append(src)
        c["detections"].append({"host": host, "port": port, "source": src,
                                 "raw": raw})

    for a in assets:
        host, src = _host_of(a), a.get("source", "")
        for p in _ports(a):
            if p.get("state") != "open":
                continue
            prod, ver = parse_service(p.get("service", ""))
            add(prod, ver, host, p.get("port"), src, p.get("service", ""))
        meta = _meta(a)
        if meta.get("tech"):
            add(str(meta["tech"]).lower(), str(meta.get("version", "")), host,
                None, "httpx", meta.get("tech"))

    # cross-reference findings by host so vulnerable builds light up
    fh = {}
    for f in findings:
        for h in re.split(r"[ ,;]+", str(f.get("hosts", ""))):
            if h.strip():
                fh.setdefault(h.strip().lower(), []).append(
                    _cve_or_title(f.get("title", "")))
    for c in comps.values():
        refs = []
        for h in c["hosts"]:
            refs += fh.get(str(h).lower(), [])
        c["findings"] = sorted(set(refs))
        c["vuln"] = len(c["findings"]) > 0
        c["host_count"] = len(c["hosts"])

    return sorted(comps.values(),
                  key=lambda c: (not c["vuln"], c["product"], c["version"]))


def search_components(components: list, query: str = "") -> list:
    q = str(query or "").strip().lower()
    if not q:
        return components
    out = []
    for c in components:
        hay = " ".join([c["product"], c["version"], " ".join(map(str, c["hosts"])),
                        " ".join(c["sources"]), " ".join(c.get("findings", []))]).lower()
        if q in hay:
            out.append(c)
    return out
