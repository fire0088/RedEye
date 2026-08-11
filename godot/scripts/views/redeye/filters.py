"""A tiny query language for filtering map nodes and defining an engagement
scope. A query is whitespace-separated clauses, ANDed together; prefix a clause
with - or ! to negate it.

    port:443                open port 443
    port:80,443,8000-8100   any of these open ports (lists + ranges)
    os:linux                OS string contains "linux"
    svc:nginx               a service/version contains "nginx"
    status:up  kind:host  source:nmap  auth:anonymous  app:OrdersApi
    open                    has at least one open port
    -port:22                does NOT have 22 open
    web01                   bare token: substring of ip/host/label/os/services

Values also accept glob wildcards (svc:*nginx*, host:web0?) and regex when
wrapped in slashes (host:/^web\\d+/). Glob is anchored -- use *x* for substring.

The matched host/endpoint nodes are the current scope; commands can be run
against all of them at once.
"""
from __future__ import annotations

import fnmatch
import re


def _tm(hay, pat) -> bool:
    """Text match with three modes, chosen by the pattern:
      /re/     -> regex search (case-insensitive)
      has * ?  -> glob (fnmatch, anchored: use *x* for substring)
      else     -> plain substring (case-insensitive)"""
    h = str(hay).lower()
    p = str(pat)
    if len(p) >= 2 and p[0] == "/" and p[-1] == "/":
        try:
            return re.search(p[1:-1], h, re.I) is not None
        except re.error:
            return False
    pl = p.lower()
    if "*" in pl or "?" in pl:
        return fnmatch.fnmatch(h, pl)
    return pl in h


class Clause:
    __slots__ = ("negate", "key", "value")

    def __init__(self, negate, key, value):
        self.negate = negate
        self.key = key
        self.value = value


def compile_query(q: str) -> list[Clause]:
    clauses = []
    for tok in (q or "").split():
        negate = False
        if tok and tok[0] in "-!":
            negate = True
            tok = tok[1:]
        if not tok:
            continue
        if ":" in tok:
            key, value = tok.split(":", 1)
            clauses.append(Clause(negate, key.lower(), value))
        else:
            clauses.append(Clause(negate, None, tok))
    return clauses


def _port_matcher(value: str):
    singles, ranges = set(), []
    for part in value.split(","):
        part = part.strip()
        if "-" in part:
            a, _, b = part.partition("-")
            if a.isdigit() and b.isdigit():
                ranges.append((int(a), int(b)))
        elif part.isdigit():
            singles.add(int(part))

    def f(port):
        try:
            p = int(port)
        except (TypeError, ValueError):
            return False
        return p in singles or any(a <= p <= b for a, b in ranges)
    return f


def _ports(host):
    return getattr(host, "ports", None) or []


def _open_ports(host):
    return [p for p in _ports(host) if p.get("state") == "open"]


def _svc_blob(host):
    out = []
    for p in _ports(host):
        out.append(str(p.get("service", "")))
        out.append(str(p.get("version", "")))
    return " ".join(out).lower()


def _meta(host, key):
    m = getattr(host, "meta", None) or {}
    return str(m.get(key, "")).lower()


def _clause_match(host, c: Clause) -> bool:
    key, val = c.key, (c.value or "")
    if key in ("port", "ports"):
        f = _port_matcher(val)
        return any(f(p.get("port")) for p in _open_ports(host))
    if key == "os":
        return _tm(getattr(host, "os", ""), val)
    if key in ("svc", "service", "software", "soft", "ver", "version"):
        return _tm(_svc_blob(host), val)
    if key == "status":
        return _tm(getattr(host, "status", ""), val)
    if key == "kind":
        return _tm(getattr(host, "kind", ""), val)
    if key in ("source", "src"):
        return _tm(getattr(host, "source", ""), val)
    if key == "ip":
        return _tm(getattr(host, "ip", ""), val)
    if key in ("host", "hostname", "name"):
        return (_tm(getattr(host, "hostname", ""), val)
                or _tm(getattr(host, "label", ""), val))
    if key == "auth":
        return _tm(_meta(host, "auth"), val)
    if key == "app":
        return _tm(_meta(host, "app"), val)
    if key == "open":
        want = val.lower() not in ("false", "0", "no")
        return bool(_open_ports(host)) == want
    if key is None and val.lower() == "open":
        return bool(_open_ports(host))
    # bare token: search across a blob of the node's identifying fields
    blob = " ".join(str(x) for x in (
        getattr(host, "ip", ""), getattr(host, "hostname", ""),
        getattr(host, "label", ""), getattr(host, "os", ""),
        getattr(host, "source", ""), _svc_blob(host),
        _meta(host, "route"), _meta(host, "app")))
    return _tm(blob, val)


def match(host, clauses: list[Clause]) -> bool:
    for c in clauses:
        ok = _clause_match(host, c)
        if c.negate:
            ok = not ok
        if not ok:
            return False
    return True


def scope_hosts(hosts, query: str) -> list:
    """Return the host/endpoint nodes matching `query`. Empty query -> no scope."""
    clauses = compile_query(query)
    if not clauses:
        return []
    return [h for h in hosts.values()
            if getattr(h, "kind", "host") in ("host", "endpoint")
            and match(h, clauses)]


def scope_ids(hosts, query: str) -> set:
    return {h.id for h in scope_hosts(hosts, query)}
