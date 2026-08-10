"""Shared helpers for REDEYE's API-backed MCP servers.

A tiny JSON-over-HTTP client (stdlib urllib -- no extra deps) plus CIDR matching
for "...in this subnet" filters. Imported by the crowdstrike / tenable / wiz
servers; the aws server uses boto3 instead.
"""
from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request


def http_json(method, url, headers=None, data=None, params=None, timeout=60):
    """Perform an HTTP request and parse a JSON response.

    data: dict/list -> sent as JSON; str/bytes -> sent as-is. Returns the parsed
    body (dict/list), or {"_raw": text} if it isn't JSON. Raises on network/HTTP
    errors so callers can fall back to mock.
    """
    if params:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params, doseq=True)
    hdrs = dict(headers or {})
    body = None
    if data is not None:
        if isinstance(data, (dict, list)):
            body = json.dumps(data).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        elif isinstance(data, str):
            body = data.encode("utf-8")
        else:
            body = data
    req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode("utf-8", "replace")
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"_raw": raw}


def oauth2_token(url, client_id, client_secret, extra=None, timeout=60):
    """OAuth2 client-credentials grant (x-www-form-urlencoded). Returns the raw
    token JSON (caller reads access_token)."""
    form = {"grant_type": "client_credentials",
            "client_id": client_id, "client_secret": client_secret}
    if extra:
        form.update(extra)
    body = urllib.parse.urlencode(form).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def in_subnet(ip, subnet) -> bool:
    """True if ip is inside subnet (CIDR). Empty subnet -> always True.
    Unparseable ip/subnet -> True (don't silently drop data)."""
    if not subnet or not ip:
        return not subnet
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        return ipaddress.ip_address(str(ip)) in net
    except ValueError:
        return True


def filter_subnet(items, subnet, ip_key="ip"):
    """Keep items whose ip_key falls in subnet. Empty subnet -> unchanged."""
    if not subnet:
        return list(items)
    return [it for it in items if in_subnet(it.get(ip_key, ""), subnet)]
