"""Read-time correlation -- merge assets and findings across sources.

Vendor-agnostic by design: correlation keys off the *normalized* fields every
source emits (ip, hostname, and the native resource id embedded in the asset id),
never off vendor names. Adding or removing a source (CrowdStrike, some other EDR,
nothing) changes nothing here -- if a source emits an ip/hostname, its records
correlate automatically.

Assets:
  - STRONG identity keys (configurable, default ip / hostname / resource_id):
    any two assets sharing a strong key value are auto-merged (union-find).
  - Manual `merge` links force a union (used to confirm a weak suggestion).
  - WEAK matches (same short hostname, different ip) are returned as
    *suggestions* for the operator to confirm or dismiss -- never auto-merged.

Findings: merged by (CVE-or-normalized-title, canonical host), where the host is
mapped through the asset clusters so "same CVE on the same box from three tools"
collapses to one finding with three sources.

Nothing is destructive: this reads raw per-source rows and returns a merged
*view*. The raw rows are untouched.
"""
from __future__ import annotations

import json
import re

DEFAULT_KEYS = ["ip", "hostname", "resource_id"]
_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

_KIND_COLOR = {
    "server": (255, 90, 90), "host": (255, 90, 90),
    "container": (90, 200, 255), "lambda": (255, 176, 0),
    "network_device": (70, 230, 160), "database": (180, 120, 255),
    "endpoint": (230, 200, 90), "cloud_resource": (150, 150, 160),
}
# more specific kinds win when members disagree
_KIND_RANK = ["lambda", "container", "database", "network_device", "server",
              "endpoint", "host", "cloud_resource"]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def prep_asset(row: dict) -> dict:
    """Normalise a raw inventory row: parse meta_json / ports_json."""
    d = dict(row)
    if isinstance(d.get("meta_json"), str):
        try:
            d["meta"] = json.loads(d["meta_json"])
        except Exception:  # noqa: BLE001
            d["meta"] = {}
    d.setdefault("meta", d.get("meta") or {})
    if isinstance(d.get("ports_json"), str):
        try:
            d["ports"] = json.loads(d["ports_json"])
        except Exception:  # noqa: BLE001
            d["ports"] = []
    d.setdefault("ports", d.get("ports") or [])
    return d


def _norm(v) -> str:
    return str(v or "").strip().lower()


def _norm_host(v) -> str:
    return _norm(v).rstrip(".")


def _resource_id(row: dict) -> str:
    rid = str(row.get("id", ""))
    return rid.split(":", 1)[1].lower() if ":" in rid else ""


def _shortname(row: dict) -> str:
    h = _norm_host(row.get("hostname"))
    return h.split(".", 1)[0] if h else ""


def key_value(row: dict, key: str) -> str:
    if key == "ip":
        return _norm(row.get("ip"))
    if key == "hostname":
        return _norm_host(row.get("hostname"))
    if key == "resource_id":
        return _resource_id(row)
    # generic: top-level field or meta
    v = row.get(key)
    if v in (None, "") and isinstance(row.get("meta"), dict):
        v = row["meta"].get(key)
    return _norm(v)


class _UF:
    def __init__(self, n):
        self.p = list(range(n))

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[ra] = rb


def _sources_of(a: dict) -> list:
    out = []
    for s in (a.get("source", ""), (a.get("meta") or {}).get("vendor", "")):
        s = str(s or "").strip()
        s = s.split(":", 1)[-1] if s.startswith("scan:") else s
        if s and s not in out:
            out.append(s)
    return out


def _pick_label(members: list) -> str:
    best = ""
    for m in members:
        lab = str(m.get("label", "")).strip()
        if not lab:
            continue
        # prefer a label that isn't just the id or a bare ip
        looks_bare = lab == str(m.get("id", "")) or lab == str(m.get("ip", ""))
        if lab and not looks_bare:
            return lab
        best = best or lab
    return best or (members[0].get("id", "") if members else "")


def _pick_kind(members: list) -> str:
    kinds = {str(m.get("kind", "") or "host") for m in members}
    for k in _KIND_RANK:
        if k in kinds:
            return k
    return next(iter(kinds), "host")


# ---------------------------------------------------------------------------
# asset correlation
# ---------------------------------------------------------------------------
def correlate_assets(rows, keys=None, merges=None, dismissed=None):
    """Return {"assets": [merged...], "suggestions": [...]}.

    keys       : strong identity keys (default ip/hostname/resource_id)
    merges     : iterable of (id_a, id_b) manual merge links (force union)
    dismissed  : iterable of frozenset({id_a, id_b}) suggestions to hide
    """
    keys = keys or DEFAULT_KEYS
    assets = [prep_asset(r) for r in rows]
    n = len(assets)
    uf = _UF(n)

    # union by strong keys
    for key in keys:
        buckets: dict[str, list[int]] = {}
        for i, a in enumerate(assets):
            val = key_value(a, key)
            if val:
                buckets.setdefault(f"{key}={val}", []).append(i)
        for idxs in buckets.values():
            for j in idxs[1:]:
                uf.union(idxs[0], j)

    # apply manual merge links
    id_to_idx = {str(a.get("id")): i for i, a in enumerate(assets)}
    for a_id, b_id in (merges or []):
        if a_id in id_to_idx and b_id in id_to_idx:
            uf.union(id_to_idx[a_id], id_to_idx[b_id])

    # gather clusters
    clusters: dict[int, list[int]] = {}
    for i in range(n):
        clusters.setdefault(uf.find(i), []).append(i)

    merged = []
    cluster_of_id = {}
    for root, idxs in clusters.items():
        members = [assets[i] for i in idxs]
        for m in members:
            cluster_of_id[str(m.get("id"))] = root
        merged.append(_merge_asset(root, members))

    # weak-match suggestions: same short hostname, different cluster
    dismissed = {frozenset(d) for d in (dismissed or [])}
    suggestions = []
    seen_pairs = set()
    short_buckets: dict[str, list[int]] = {}
    for i, a in enumerate(assets):
        sn = _shortname(a)
        if sn:
            short_buckets.setdefault(sn, []).append(i)
    for sn, idxs in short_buckets.items():
        roots = {}
        for i in idxs:
            roots.setdefault(uf.find(i), i)
        rootlist = list(roots.items())
        for x in range(len(rootlist)):
            for y in range(x + 1, len(rootlist)):
                ia, ib = rootlist[x][1], rootlist[y][1]
                id_a, id_b = str(assets[ia]["id"]), str(assets[ib]["id"])
                pair = frozenset({id_a, id_b})
                if pair in dismissed or pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                suggestions.append({
                    "a": id_a, "b": id_b,
                    "a_label": assets[ia].get("label", id_a),
                    "b_label": assets[ib].get("label", id_b),
                    "reason": f"same hostname '{sn}', different address",
                    "confidence": "medium",
                })

    merged.sort(key=lambda m: (-len(m["sources"]), m["label"].lower()))
    return {"assets": merged, "suggestions": suggestions,
            "_cluster_of_id": cluster_of_id}


def _merge_asset(root, members):
    ips = [m.get("ip") for m in members if m.get("ip")]
    hosts = [m.get("hostname") for m in members if m.get("hostname")]
    oses = [m.get("os") for m in members if m.get("os")]
    sources = []
    for m in members:
        for s in _sources_of(m):
            if s not in sources:
                sources.append(s)
    ports = {}
    for m in members:
        for p in (m.get("ports") or []):
            ports[p.get("port")] = p
    meta = {}
    for m in members:
        if isinstance(m.get("meta"), dict):
            meta.update(m["meta"])
    kind = _pick_kind(members)
    return {
        "id": f"corr:{root}",
        "label": _pick_label(members),
        "kind": kind,
        "ip": ips[0] if ips else "",
        "ips": sorted(set(ips)),
        "hostname": hosts[0] if hosts else "",
        "os": oses[0] if oses else "",
        "status": next((m.get("status") for m in members if m.get("status")), ""),
        "sources": sources,
        "source_count": len(sources),
        "member_ids": [str(m.get("id")) for m in members],
        "member_count": len(members),
        "in_scope": 1 if any(int(m.get("in_scope", 1)) for m in members) else 0,
        "open_count": max((int(m.get("open_count", 0) or 0) for m in members),
                          default=0),
        "ports": list(ports.values()),
        "meta": meta,
        "color": list(_KIND_COLOR.get(kind, (150, 150, 160))),
    }


# ---------------------------------------------------------------------------
# finding correlation
# ---------------------------------------------------------------------------
def _cve_or_title(f: dict) -> str:
    t = str(f.get("title", ""))
    m = _CVE.search(t)
    if m:
        return m.group(0).upper()
    return t.strip().lower()[:120] or "untitled"


def correlate_findings(finding_rows, merged_assets):
    """Merge findings by (CVE-or-title, canonical host). merged_assets is the
    output of correlate_assets()["assets"] -- used to canonicalise hosts."""
    # build host-token -> canonical asset label/id
    host_index = {}
    for a in merged_assets:
        canon = a.get("label") or a.get("id")
        for tok in a.get("ips", []) + ([a.get("hostname")] if a.get("hostname") else []):
            if tok:
                host_index[_norm_host(tok)] = canon
                host_index[_norm(tok)] = canon

    groups: dict[tuple, dict] = {}
    for r in finding_rows:
        f = dict(r)
        vuln = _cve_or_title(f)
        raw_host = str(f.get("hosts", "")).strip()
        canon = host_index.get(_norm_host(raw_host), raw_host)
        key = (vuln, _norm(canon))
        src = str(f.get("source", "") or "manual")
        src = src.split(":", 1)[-1] if src.startswith("scan:") else src
        if key not in groups:
            groups[key] = {
                "title": f.get("title", vuln),
                "severity": f.get("severity", "MEDIUM"),
                "hosts": canon,
                "status": f.get("status", "open"),
                "description": f.get("description", ""),
                "recommendation": f.get("recommendation", ""),
                "cvss": f.get("cvss", ""), "cwe": f.get("cwe", ""),
                "evidence": f.get("evidence", ""),
                "sources": [], "member_ids": [], "cve": vuln if vuln.upper().startswith("CVE") else "",
            }
        g = groups[key]
        if src and src not in g["sources"]:
            g["sources"].append(src)
        if f.get("id") is not None:
            g["member_ids"].append(f.get("id"))
        # keep the max severity + prefer any non-empty text
        if _SEV_ORDER.get(str(f.get("severity", "")).upper(), 0) > \
           _SEV_ORDER.get(str(g["severity"]).upper(), 0):
            g["severity"] = f.get("severity")
        for fld in ("description", "recommendation", "cvss", "cwe", "evidence"):
            if not g.get(fld) and f.get(fld):
                g[fld] = f[fld]
        if str(f.get("status")) == "open":
            g["status"] = "open"

    out = list(groups.values())
    for g in out:
        g["source_count"] = len(g["sources"])
        g["member_count"] = len(g["member_ids"])
    out.sort(key=lambda g: (-_SEV_ORDER.get(str(g["severity"]).upper(), 0),
                            -g["source_count"]))
    return out
