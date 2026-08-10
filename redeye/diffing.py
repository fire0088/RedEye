"""Scan diffing / change tracking.

Take a point-in-time snapshot of the inventory + findings, then diff a later
state against it: new/removed hosts, newly-opened / newly-closed ports per host,
and new / resolved findings. Pure functions over plain rows so it's testable and
independent of the DB (the daemon persists snapshots as JSON).
"""
from __future__ import annotations

import json
import re

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _cve_or_title(title: str) -> str:
    m = _CVE.search(str(title or ""))
    return m.group(0).upper() if m else str(title or "").strip().lower()[:120]


def _asset_map(rows) -> dict:
    out = {}
    for r in rows:
        d = dict(r)
        try:
            ports = json.loads(d.get("ports_json") or "[]")
        except Exception:  # noqa: BLE001
            ports = d.get("ports") or []
        openp = {int(p["port"]): p.get("service", "")
                 for p in ports if p.get("state") == "open" and p.get("port") is not None}
        out[str(d.get("id"))] = {"label": d.get("label", ""), "ip": d.get("ip", ""),
                                 "hostname": d.get("hostname", ""), "ports": openp}
    return out


def _finding_map(rows) -> dict:
    out = {}
    for r in rows:
        d = dict(r)
        key = f"{_cve_or_title(d.get('title', ''))}|{str(d.get('hosts', '')).lower()}"
        out[key] = {"severity": d.get("severity", ""), "title": d.get("title", ""),
                    "hosts": d.get("hosts", "")}
    return out


def make_snapshot(assets_rows, findings_rows) -> dict:
    return {"assets": _asset_map(assets_rows), "findings": _finding_map(findings_rows)}


def diff(old: dict, new: dict) -> dict:
    oa, na = old.get("assets", {}), new.get("assets", {})
    new_hosts = [na[k] for k in na if k not in oa]
    removed_hosts = [oa[k] for k in oa if k not in na]
    port_changes = []
    for k in na:
        if k in oa:
            before, after = set(oa[k]["ports"]), set(na[k]["ports"])
            opened, closed = sorted(after - before), sorted(before - after)
            if opened or closed:
                port_changes.append({
                    "host": na[k]["label"] or na[k]["ip"] or na[k]["hostname"],
                    "opened": opened, "closed": closed})

    of, nf = old.get("findings", {}), new.get("findings", {})
    new_findings = [nf[k] for k in nf if k not in of]
    resolved = [of[k] for k in of if k not in nf]

    return {
        "new_hosts": new_hosts, "removed_hosts": removed_hosts,
        "port_changes": port_changes, "new_findings": new_findings,
        "resolved_findings": resolved,
        "summary": {
            "new_hosts": len(new_hosts), "removed_hosts": len(removed_hosts),
            "port_changes": len(port_changes), "new_findings": len(new_findings),
            "resolved_findings": len(resolved),
        },
    }
