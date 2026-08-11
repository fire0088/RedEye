"""Engagement scope -- the targets the operator is cleared to act against.

Entries may be:
  - a CIDR            10.0.0.0/24
  - a single IP       10.0.0.5
  - a hostname/domain corp.example.com   (matches it and any subdomain)
  - a URL             https://app.example.com/...   (its host is used)

An EMPTY scope means "unrestricted" -- nothing is blocked. The guardrail only
engages once at least one entry is defined.

Two consumers:
  - enforcement: MCPManager.call blocks a tool whose target argument is out of
    scope (the inventory-enumeration tools are exempt -- see SCOPE_EXEMPT_TOOLS
    in mcp_manager).
  - inventory tagging: each discovered asset is flagged in/out of scope. The
    inventory itself is never blocked -- you can enumerate everything.
"""
from __future__ import annotations

import ipaddress
import threading
from urllib.parse import urlparse

# tool-arg keys that name a target we should scope-check
TARGET_KEYS = ("target", "targets", "host", "hosts", "ip", "url", "urls",
               "subnet", "cidr", "range")


class Scope:
    def __init__(self, entries=None):
        self._entries: list[str] = []
        self._lock = threading.Lock()
        self.set(entries or [])

    def set(self, entries) -> None:
        cleaned = []
        for e in entries or []:
            s = str(e).strip()
            if s:
                cleaned.append(s)
        with self._lock:
            self._entries = cleaned

    def entries(self) -> list:
        with self._lock:
            return list(self._entries)

    def is_empty(self) -> bool:
        with self._lock:
            return len(self._entries) == 0

    # -- matching -----------------------------------------------------------
    def in_scope(self, value) -> bool:
        """True if value (ip / hostname / url / cidr) is within scope.
        Empty scope -> everything is in scope."""
        entries = self.entries()
        if not entries:
            return True
        host = _host_of(value)
        if not host:
            return True                      # nothing target-like -> allow
        return any(_match(host, e) for e in entries)

    def check_args(self, args) -> tuple[bool, str]:
        """Scan a tool's args for target-like values. Returns (ok, offending).
        ok=True when every target found is in scope (or none / empty scope)."""
        if self.is_empty() or not isinstance(args, dict):
            return True, ""
        for k, v in args.items():
            if str(k).lower() not in TARGET_KEYS:
                continue
            for tok in _tokens(v):
                if not self.in_scope(tok):
                    return False, tok
        return True, ""

    def matches_asset(self, ip, hostname) -> bool:
        """Is an asset (by ip and/or hostname) in scope? Empty scope -> True."""
        if self.is_empty():
            return True
        return (bool(ip) and self.in_scope(ip)) or \
               (bool(hostname) and self.in_scope(hostname))


def _tokens(v):
    if isinstance(v, (list, tuple)):
        out = []
        for x in v:
            out += _tokens(x)
        return out
    s = str(v).strip()
    if not s:
        return []
    parts = [p for chunk in s.split(",") for p in chunk.split()]
    return parts or [s]


def _host_of(value) -> str:
    s = str(value).strip()
    if not s:
        return ""
    if "://" in s:
        return urlparse(s).hostname or ""
    # strip a trailing :port for host:port (but leave CIDR and IPv6 alone)
    if "/" not in s and s.count(":") == 1 and not _is_ipv6(s):
        s = s.split(":")[0]
    return s


def _is_ipv6(s) -> bool:
    try:
        return isinstance(ipaddress.ip_address(s), ipaddress.IPv6Address)
    except ValueError:
        return False


def _match(host: str, entry: str) -> bool:
    # CIDR / IP entry
    try:
        net = ipaddress.ip_network(entry, strict=False)
        try:
            if "/" in host:
                sub = ipaddress.ip_network(host, strict=False)
                try:
                    return sub.subnet_of(net)
                except (TypeError, ValueError):
                    return False
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False
    except ValueError:
        pass
    # hostname / domain entry (leading "*." or "." is tolerated)
    e = entry.lower().lstrip("*.").rstrip(".")
    h = host.lower().rstrip(".")
    if not e:
        return False
    return h == e or h.endswith("." + e)
