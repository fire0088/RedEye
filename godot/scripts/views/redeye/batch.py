"""Batch operations -- run one tool against many host/port endpoints at once.

Endpoints come from either a saved LABEL (a named set of host+port pairs, e.g.
"the 14 boxes running the same portal") or a live FILTER query (filters.py).
The batch runner (worker.py) fans a single tool across every endpoint -- probe
them all with the same credential, scan them all with nuclei, etc. Scope
enforcement still happens per target in MCPManager.call, so out-of-scope
endpoints are blocked automatically.

This module holds the pure, testable parts: adapting inventory rows to the
filter interface, selecting rows by query, and expanding assets into endpoints
(with a best-effort URL for web services).
"""
from __future__ import annotations

import json
import re

from . import filters as F

WEB_HINTS = ("http", "https", "www", "nginx", "apache", "iis", "tomcat",
             "caddy", "httpd", "lighttpd")
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000}


class RowHost:
    """Adapt a parsed inventory row (dict) to the attribute interface that
    filters.py expects (it uses getattr)."""
    __slots__ = ("id", "ip", "hostname", "label", "os", "status", "kind",
                 "source", "ports", "meta")

    def __init__(self, row):
        self.id = row.get("id", "")
        self.ip = row.get("ip", "")
        self.hostname = row.get("hostname", "")
        self.label = row.get("label", "")
        self.os = row.get("os", "")
        self.status = row.get("status", "")
        self.kind = row.get("kind", "")
        self.source = row.get("source", "")
        self.ports = row.get("ports") or []
        self.meta = row.get("meta") or {}


def parse_row(row) -> dict:
    d = dict(row)
    if isinstance(d.get("ports_json"), str):
        try:
            d["ports"] = json.loads(d["ports_json"])
        except Exception:  # noqa: BLE001
            d["ports"] = []
    if isinstance(d.get("meta_json"), str):
        try:
            d["meta"] = json.loads(d["meta_json"])
        except Exception:  # noqa: BLE001
            d["meta"] = {}
    d.setdefault("ports", d.get("ports") or [])
    d.setdefault("meta", d.get("meta") or {})
    return d


def select_rows(rows, query: str):
    """RowHosts matching a filter DSL query. Empty query -> all rows."""
    hosts = [RowHost(parse_row(r)) for r in rows]
    clauses = F.compile_query(query or "")
    if not clauses:
        return hosts
    return [h for h in hosts if F.match(h, clauses)]


def _scheme(service, port) -> str:
    s = str(service or "").lower()
    try:
        p = int(port) if port is not None else None
    except (TypeError, ValueError):
        p = None
    if "https" in s or p in (443, 8443):
        return "https"
    if "http" in s or any(w in s for w in WEB_HINTS) or p in (80, 8080, 8000, 8888, 3000, 5000):
        return "http"
    return ""


def _endpoint(host: RowHost, port_entry) -> dict:
    ip = host.ip or ""
    hn = host.hostname or ""
    hoststr = hn or ip or host.label
    port = port_entry.get("port") if port_entry else None
    service = port_entry.get("service", "") if port_entry else ""
    scheme = _scheme(service, port) if port else ""
    url = ""
    if scheme and port:
        url = (f"{scheme}://{hoststr}" if port in (80, 443)
               else f"{scheme}://{hoststr}:{port}")
    target = url or (f"{hoststr}:{port}" if port else hoststr)
    return {"asset_id": host.id, "ip": ip, "hostname": hn, "host": hoststr,
            "port": port, "service": service, "scheme": scheme, "url": url,
            "target": target}


def _choose_ports(ports, portspec):
    openp = [p for p in ports if p.get("state") == "open"]
    ps = str(portspec or "web").lower()
    if ps == "host":
        return []
    if ps == "web":
        return [p for p in openp if _scheme(p.get("service", ""), p.get("port"))]
    if ps == "open":
        return openp
    if ps == "all":
        return ports
    matcher = F._port_matcher(ps)
    return [p for p in openp if matcher(p.get("port"))]


def endpoints_for_rows(rows, query="", portspec="web"):
    """Expand assets matching `query` into endpoints. portspec:
    'web' (web ports only), 'open', 'all', 'host' (one endpoint per host, no
    port), or a port list like '443,8443'. Hosts with no matching port are
    skipped, except for portspec 'host'."""
    hosts = select_rows(rows, query)
    out = []
    ps = str(portspec or "web").lower()
    for h in hosts:
        chosen = _choose_ports(h.ports, portspec)
        if chosen:
            for p in chosen:
                out.append(_endpoint(h, p))
        elif ps == "host":
            out.append(_endpoint(h, None))
    return out


def endpoint_from_row(row, port=None):
    """Build a single endpoint for a labeled (asset, port) member."""
    h = RowHost(parse_row(row))
    pe = None
    if port not in (None, "", -1, "-1"):
        pe = next((p for p in h.ports if str(p.get("port")) == str(port)),
                  {"port": int(port), "service": ""})
    return _endpoint(h, pe)


# ---------------------------------------------------------------------------
# service fingerprinting -> auto-labelling
# ---------------------------------------------------------------------------
# ordered so more specific names win (openssh before ssh, mariadb before maria)
_APP_HINTS = [
    "nginx", "apache", "httpd", "lighttpd", "caddy", "iis", "tomcat", "jetty",
    "weblogic", "jboss", "wildfly", "openssh", "ssh", "postgres", "postgresql",
    "mariadb", "mysql", "mssql", "oracle", "redis", "mongodb", "memcached",
    "elasticsearch", "kibana", "rabbitmq", "kafka", "jenkins", "gitlab",
    "grafana", "prometheus", "jira", "confluence", "exchange", "rdp", "vnc",
    "smb", "ftp", "telnet", "ldap", "kubernetes", "docker", "consul", "vault",
    "wordpress", "drupal", "joomla", "php", "node", "express", "flask",
    "django", "spring", "http", "https",
]


def service_family(service: str) -> str:
    """Normalise a service/version string to a coarse family (drops versions)."""
    s = str(service or "").lower()
    for app in _APP_HINTS:
        if app in s:
            return app
    toks = [t for t in re.split(r"[^a-z0-9]+", s)
            if t and not any(ch.isdigit() for ch in t)]
    return toks[0] if toks else ""


def signature_of(service, port) -> str:
    fam = service_family(service) or "port"
    return f"{fam}:{port}" if port else fam


def auto_group(rows, portspec="web", min_group=2):
    """Group endpoints by (service-family, port) signature. Returns one entry
    per group with >= min_group members:
        [{"signature", "label", "endpoints": [...], "count"}]"""
    eps = endpoints_for_rows(rows, "", portspec)
    groups: dict[str, list] = {}
    for ep in eps:
        sig = signature_of(ep.get("service"), ep.get("port"))
        groups.setdefault(sig, []).append(ep)
    out = []
    for sig, members in groups.items():
        if len(members) >= max(2, int(min_group)):
            out.append({"signature": sig, "label": f"auto/{sig}",
                        "endpoints": members, "count": len(members)})
    out.sort(key=lambda g: -g["count"])
    return out


def endpoints_like(rows, asset_id, port=None):
    """Find every endpoint sharing the given asset/port's service+port
    signature. If port is None, use the asset's first web (else first open)
    port. Returns (signature, endpoints, default_label)."""
    parsed = {str(r.get("id")): parse_row(r) for r in rows}
    seed = parsed.get(str(asset_id))
    if not seed:
        return ("", [], "")
    seed_ports = seed.get("ports") or []
    if port in (None, "", -1, "-1"):
        web = [p for p in seed_ports
               if p.get("state") == "open" and _scheme(p.get("service", ""), p.get("port"))]
        openp = [p for p in seed_ports if p.get("state") == "open"]
        chosen = (web or openp)
        if not chosen:
            return ("", [], "")
        pe = chosen[0]
    else:
        pe = next((p for p in seed_ports if str(p.get("port")) == str(port)),
                  {"port": port, "service": ""})
    sig = signature_of(pe.get("service"), pe.get("port"))

    matches = []
    for row in parsed.values():
        h = RowHost(row)
        for p in (h.ports or []):
            if p.get("state") != "open":
                continue
            if signature_of(p.get("service"), p.get("port")) == sig:
                matches.append(_endpoint(h, p))
    return (sig, matches, f"like/{sig}")
