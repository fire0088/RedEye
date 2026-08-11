"""Turn tool results into map nodes, findings, and vault entries.

Each server type registers an extractor keyed by the "extractor" field in
mcp_config.json. An extractor receives (tool_name, parsed_json) and yields any
mix of:
  - HostUpsert    -> a node on the network map
  - FindingUpsert -> a row in the findings DB (scanners like nuclei/wapiti)
  - VaultUpsert   -> a credential/secret in the key vault

Unknown servers contribute nothing (chat still shows their output). Adding a new
integration = write one function here and tag the config -- no other changes.
See servers/_template_server.py for the emit-shapes.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Iterable

from .bridge import FindingUpsert, HostUpsert, ScreenshotUpsert, VaultUpsert

Event = Any  # HostUpsert | FindingUpsert | VaultUpsert
Extractor = Callable[[str, Any], Iterable[Event]]
_REGISTRY: dict[str, Extractor] = {}


def register(name: str):
    def deco(fn: Extractor) -> Extractor:
        _REGISTRY[name] = fn
        return fn
    return deco


def extract(extractor_name: str, source_key: str, tool_name: str,
            text: str, structured: Any) -> list[Event]:
    fn = _REGISTRY.get(extractor_name)
    if not fn:
        return []
    data = structured
    if data is None:
        try:
            data = json.loads(text) if text and text.strip().startswith(("{", "[")) else None
        except json.JSONDecodeError:
            data = None
    if data is None:
        return []
    out: list[Event] = []
    try:
        for ev in fn(tool_name, data):
            if hasattr(ev, "source"):
                ev.source = source_key
            out.append(ev)
    except Exception:  # noqa: BLE001 - never let a bad payload crash the app
        return []
    return out


# -- shared helpers ----------------------------------------------------------
_SEV_MAP = {
    "critical": "CRITICAL", "crit": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM", "moderate": "MEDIUM", "med": "MEDIUM",
    "low": "LOW",
    "info": "INFO", "informational": "INFO", "unknown": "INFO",
}


def _sev(x: Any) -> str:
    if isinstance(x, (int, float)):
        return ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"][min(4, max(0, int(x)))]
    return _SEV_MAP.get(str(x or "").strip().lower(), "MEDIUM")


# ---------------------------------------------------------------------------
# nmap
# ---------------------------------------------------------------------------
@register("nmap")
def _nmap(tool_name: str, data: Any) -> Iterable[HostUpsert]:
    hosts = data.get("hosts", []) if isinstance(data, dict) else []
    for h in hosts:
        ip = h.get("ip", "")
        if not ip:
            continue
        ports = h.get("ports", [])
        open_ports = [p for p in ports if p.get("state") == "open"]
        label = h.get("hostname") or ip
        yield HostUpsert(
            id=f"nmap:{ip}",
            label=label,
            source="",  # filled by extract()
            kind="host",
            ip=ip,
            hostname=h.get("hostname", ""),
            os=h.get("os", ""),
            status=h.get("status", "up"),
            ports=ports,
            meta={"open_count": len(open_ports), "mock": data.get("mock", False)},
            color=(255, 90, 90) if open_ports else (150, 150, 160),
        )


# ---------------------------------------------------------------------------
# roslyn .NET endpoint discovery
# (schema mirrors the reachnet Roslyn extractor: route, verb, auth, handler)
# ---------------------------------------------------------------------------
@register("roslyn")
def _roslyn(tool_name: str, data: Any) -> Iterable[HostUpsert]:
    apps = data.get("apps") if isinstance(data, dict) else None
    if apps is None and isinstance(data, dict) and "endpoints" in data:
        apps = [data]
    for app in (apps or []):
        app_name = app.get("app") or app.get("name") or "webapp"
        base = app.get("base_url", "")
        for ep in app.get("endpoints", []):
            route = ep.get("route", "/")
            verb = ep.get("verb", "ANY")
            auth = ep.get("auth", "unknown")
            handler = ep.get("handler", "")
            eid = f"roslyn:{app_name}:{verb}:{route}"
            # colour by auth posture: anonymous endpoints are the juicy ones
            if auth in ("anonymous", "allow_anonymous", "none"):
                color = (255, 70, 70)
            elif auth in ("authenticated", "authorize", "authorized"):
                color = (90, 200, 130)
            else:
                color = (230, 200, 90)
            yield HostUpsert(
                id=eid,
                label=f"{verb} {route}",
                source="",
                kind="endpoint",
                hostname=app_name,
                status="up",
                meta={"app": app_name, "base_url": base, "verb": verb,
                      "auth": auth, "handler": handler, "route": route,
                      "mock": data.get("mock", False)},
                color=color,
            )


# ---------------------------------------------------------------------------
# secret / credential ingestion
# Reads data["secrets"] and/or data["credentials"]: lists of
#   {kind?, label?, username?, secret|password|value, scope?, notes?}
# Any server can include these arrays to push finds into the key vault.
# ---------------------------------------------------------------------------
@register("secret")
def _secret(tool_name: str, data: Any) -> Iterable[Event]:
    if not isinstance(data, dict):
        return
    items = list(data.get("secrets", [])) + list(data.get("credentials", []))
    for it in items:
        secret = it.get("secret") or it.get("password") or it.get("value") or ""
        if not secret and not it.get("username"):
            continue
        yield VaultUpsert(
            kind=it.get("kind", "credential" if it.get("username") else "secret"),
            label=it.get("label", ""),
            username=it.get("username", ""),
            secret=secret,
            scope=it.get("scope", "") or it.get("host", "") or it.get("url", ""),
            notes=it.get("notes", ""),
        )


# ---------------------------------------------------------------------------
# nuclei -- vulnerability scanner. Emits findings (+ host nodes, + any secrets
# a template extracted). Expected JSON: {"findings": [ ... ], "mock": bool}
#   finding: {template_id, name, severity, host, matched_at, description?,
#             remediation?, secret?}
# ---------------------------------------------------------------------------
@register("nuclei")
def _nuclei(tool_name: str, data: Any) -> Iterable[Event]:
    if not isinstance(data, dict):
        return
    seen_hosts = set()
    for f in data.get("findings", []):
        tid = f.get("template_id", f.get("template", "finding"))
        matched = f.get("matched_at") or f.get("url") or f.get("host", "")
        host = f.get("host", "") or matched
        name = f.get("name", tid)
        sev = _sev(f.get("severity", "info"))
        yield FindingUpsert(
            dedupe=f"nuclei:{tid}:{matched}",
            title=f"{name}",
            severity=sev,
            hosts=matched,
            description=f.get("description", "")
            or f"nuclei template '{tid}' matched at {matched}.",
            recommendation=f.get("remediation", "")
            or "Validate the finding and remediate per the template reference.",
        )
        if host and host not in seen_hosts:
            seen_hosts.add(host)
            yield HostUpsert(
                id=f"nuclei:{host}", label=host, source="", kind="host",
                hostname=host, status="up",
                meta={"open_count": 0, "scanner": "nuclei"},
                color=(255, 120, 60))
        secret = f.get("secret") or f.get("extracted_secret")
        if secret:
            yield VaultUpsert(kind="secret", label=name, secret=str(secret),
                              scope=matched, notes=f"nuclei:{tid}")


# ---------------------------------------------------------------------------
# wapiti -- web app vulnerability scanner. Expected JSON:
#   {"target": url, "vulnerabilities": [ {category, level, path, info, ...} ],
#    "mock": bool}    (also accepts wapiti's native {"vulnerabilities": {cat: [..]}})
# ---------------------------------------------------------------------------
@register("wapiti")
def _wapiti(tool_name: str, data: Any) -> Iterable[Event]:
    if not isinstance(data, dict):
        return
    target = data.get("target", "")
    vulns = data.get("vulnerabilities", [])
    # normalise wapiti's native {category: [entries]} form to a flat list
    if isinstance(vulns, dict):
        flat = []
        for cat, entries in vulns.items():
            for e in (entries or []):
                e = dict(e)
                e.setdefault("category", cat)
                flat.append(e)
        vulns = flat
    host = target
    if host:
        yield HostUpsert(id=f"wapiti:{host}", label=host, source="",
                         kind="host", hostname=host, status="up",
                         meta={"open_count": 0, "scanner": "wapiti"},
                         color=(180, 120, 255))
    for v in vulns:
        cat = v.get("category", "Web vulnerability")
        path = v.get("path", "") or v.get("url", "") or target
        yield FindingUpsert(
            dedupe=f"wapiti:{cat}:{path}",
            title=f"{cat}",
            severity=_sev(v.get("level", v.get("severity", "medium"))),
            hosts=(target + path) if path.startswith("/") else (path or target),
            description=v.get("info", "") or f"{cat} reported by wapiti at {path}.",
            recommendation=v.get("solution", "")
            or "Remediate per OWASP guidance for this vulnerability class.",
        )


# ---------------------------------------------------------------------------
# cloud / vulnerability-management integrations (aws, crowdstrike, tenable, wiz)
# Normalised schema so one extractor serves all four:
#   {"vendor": str, "mock": bool,
#    "assets":   [{id, kind, label, ip?, hostname?, os?, status?, region?,
#                  account?, ports?, meta?}],
#    "findings": [{id?, cve?, title?, severity, asset?, ip?, description?,
#                  recommendation?}]}
# Assets -> inventory/map nodes (coloured by kind); findings -> findings DB.
# ---------------------------------------------------------------------------
_KIND_COLOR = {
    "server": (255, 90, 90), "host": (255, 90, 90),
    "container": (90, 200, 255),
    "lambda": (255, 176, 0),
    "network_device": (70, 230, 160),
    "database": (180, 120, 255),
    "endpoint": (230, 200, 90),
    "cloud_resource": (150, 150, 160),
}


def _cloud(tool_name: str, data: Any) -> Iterable[Event]:
    if not isinstance(data, dict):
        return
    vendor = data.get("vendor", "cloud")
    mock = data.get("mock", False)
    for a in data.get("assets", []):
        kind = a.get("kind", "cloud_resource")
        native = a.get("id") or a.get("label") or a.get("ip") or "asset"
        yield HostUpsert(
            id=f"{vendor}:{native}",
            label=a.get("label") or a.get("hostname") or a.get("ip") or str(native),
            source="",  # filled by extract()
            kind=kind,
            ip=a.get("ip", ""),
            hostname=a.get("hostname", ""),
            os=a.get("os", ""),
            status=a.get("status", "") or "up",
            ports=a.get("ports", []),
            meta={**(a.get("meta") or {}), "vendor": vendor,
                  "region": a.get("region", ""), "account": a.get("account", ""),
                  "mock": mock},
            color=_KIND_COLOR.get(kind, (150, 150, 160)),
        )
    for f in data.get("findings", []):
        cve = f.get("cve", "")
        title = f.get("title", "") or cve or "Vulnerability"
        if cve and cve not in title:
            title = f"{cve} {title}".strip()
        asset = f.get("asset", "") or f.get("ip", "") or f.get("hostname", "")
        native = f.get("id") or cve or title
        yield FindingUpsert(
            dedupe=f"{vendor}:{native}:{asset}",
            title=title,
            severity=_sev(f.get("severity", "medium")),
            hosts=asset,
            description=f.get("description", "") or f"{title} reported by {vendor}.",
            recommendation=f.get("recommendation", "") or f.get("solution", "")
            or "Review and remediate per vendor guidance.",
        )


# one function, registered for each vendor so mcp_config reads naturally
for _name in ("aws", "crowdstrike", "tenable", "wiz", "probe", "httpx", "subfinder", "masscan", "trivy"):
    register(_name)(_cloud)


@register("gowitness")
def _gowitness(tool_name: str, data: Any) -> Iterable[Event]:
    if not isinstance(data, dict):
        return
    for s in data.get("screenshots", []):
        yield ScreenshotUpsert(
            url=s.get("url", ""), asset=s.get("asset", "") or s.get("url", ""),
            title=s.get("title", ""), image_b64=s.get("image_b64", ""),
            status=int(s.get("status", 0) or 0), phash=s.get("phash", ""))
