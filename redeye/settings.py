"""Load app settings from a config.cfg (INI) file so the command line stays
optional. CLI flags, when given, override whatever is here.

Sections: [display] [audio] [aws] [paths] [vault]. Missing file or missing
keys fall back to DEFAULTS, so REDEYE always starts.
"""
from __future__ import annotations

import configparser
import os

DEFAULTS: dict[str, dict[str, str]] = {
    "display": {"size": "1360x820", "crt": "true", "fullscreen": "false"},
    "audio":   {"enabled": "true", "volume": "0.8"},
    "aws":     {"profile": "", "region": "us-east-1", "model": ""},
    "paths":   {"mcp_config": "mcp_config.json", "db": "redeye.db",
                "exports": "exports"},
    "vault":   {"encrypt": "false", "passphrase": ""},
    "jira":    {"base_url": "", "project": "SEC", "email": "", "token": ""},
    "server":  {"host": "127.0.0.1", "port": "8787", "password": ""},
    "tools":   {"auto_install": "true"},
    "scope":   {"targets": ""},
    "correlate": {"keys": "ip, hostname, resource_id"},
    "approval": {"dangerous": "brute, spray, exploit, probe, attack, login, password, cred, shell, rce, inject"},
    "engagement": {"client": "", "tester": "", "window": "", "contact": ""},
}

_TRUE = {"1", "true", "yes", "on"}


def load(path: str | None) -> dict:
    """Return a nested dict of settings, with a '_base_dir' key for resolving
    relative paths against the config file's location."""
    data = {sec: dict(vals) for sec, vals in DEFAULTS.items()}
    base = "."
    if path and os.path.isfile(path):
        base = os.path.dirname(os.path.abspath(path)) or "."
        cp = configparser.ConfigParser()
        try:
            cp.read(path, encoding="utf-8")
            for sec in cp.sections():
                data.setdefault(sec, {})
                for k, v in cp.items(sec):
                    data[sec][k] = v
        except configparser.Error:
            pass
    data["_base_dir"] = base
    return data


def get(s: dict, section: str, key: str, default: str = "") -> str:
    return s.get(section, {}).get(key, default)


def get_bool(s: dict, section: str, key: str, default: bool = False) -> bool:
    v = get(s, section, key, "").strip().lower()
    return (v in _TRUE) if v else default


def get_float(s: dict, section: str, key: str, default: float = 0.0) -> float:
    try:
        return float(get(s, section, key, "").strip())
    except (TypeError, ValueError):
        return default


def parse_size(s: str, default=(1360, 820)) -> tuple[int, int]:
    try:
        w, h = s.lower().split("x")
        return int(w), int(h)
    except (ValueError, AttributeError):
        return default


def resolve(s: dict, rel: str) -> str:
    """Resolve a possibly-relative path against the config file's directory."""
    if os.path.isabs(rel):
        return rel
    return os.path.normpath(os.path.join(s.get("_base_dir", "."), rel))


def write_value(path, section, key, value):
    """Upsert `key = value` under [section] in an INI file, preserving comments
    and other sections. Creates the file/section if missing. Best-effort."""
    import os, re
    try:
        text = open(path, encoding="utf-8").read() if os.path.isfile(path) else ""
    except OSError:
        text = ""
    lines = text.splitlines()
    head = "[" + section + "]"
    has = any(ln.strip().lower() == head.lower() for ln in lines)
    out = []
    if has:
        in_sec = False
        wrote = False
        for ln in lines:
            st = ln.strip()
            if st.lower() == head.lower():
                in_sec = True
                out.append(ln)
                continue
            if in_sec and st.startswith("[") and st.endswith("]"):
                if not wrote:
                    out.append(f"{key} = {value}")
                    wrote = True
                in_sec = False
                out.append(ln)
                continue
            if in_sec and re.match(r"(?i)\s*" + re.escape(key) + r"\s*=", ln):
                out.append(f"{key} = {value}")
                wrote = True
                continue
            out.append(ln)
        if in_sec and not wrote:
            out.append(f"{key} = {value}")
    else:
        out = lines[:]
        if out and out[-1].strip() != "":
            out.append("")
        out += [head, f"{key} = {value}"]
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")
        return True
    except OSError:
        return False
