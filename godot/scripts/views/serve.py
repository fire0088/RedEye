#!/usr/bin/env python3
"""Run the REDEYE backend daemon (headless, multiplayer).

Loads config.cfg + the MCP registry, generates a fresh access password, writes
it into config.cfg under [server], and serves the Bedrock/MCP/database core over
a TCP socket. Any username plus that password may connect; everyone shares one
session.

    python serve.py                       # 127.0.0.1:8787
    python serve.py --host 0.0.0.0        # let other machines connect (LAN)
    python serve.py --port 9000 --config other.cfg
    python serve.py --keep-password       # reuse [server]password instead of rotating
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys

from redeye import settings as S
from redeye.daemon import DEFAULT_HOST, DEFAULT_PORT, RedeyeDaemon


def _gen_password() -> str:
    # readable-ish: three short url-safe groups
    return "-".join(secrets.token_urlsafe(4) for _ in range(3))


def persist_password(path: str, password: str) -> bool:
    """Upsert `password = ...` under a [server] section, preserving comments and
    the rest of the file. Creates the file / section if missing."""
    try:
        text = open(path, encoding="utf-8").read() if os.path.isfile(path) else ""
    except OSError:
        text = ""
    lines = text.splitlines()
    has_server = any(ln.strip().lower() == "[server]" for ln in lines)
    out = []
    if has_server:
        in_server = False
        wrote = False
        for ln in lines:
            stripped = ln.strip()
            if stripped.lower() == "[server]":
                in_server = True
                out.append(ln)
                continue
            if in_server and stripped.startswith("[") and stripped.endswith("]"):
                if not wrote:
                    out.append(f"password = {password}")
                    wrote = True
                in_server = False
                out.append(ln)
                continue
            if in_server and re.match(r"(?i)\s*password\s*=", ln):
                out.append(f"password = {password}")
                wrote = True
                continue
            out.append(ln)
        if in_server and not wrote:
            out.append(f"password = {password}")
    else:
        out = lines[:]
        if out and out[-1].strip() != "":
            out.append("")
        out += [
            "[server]",
            "# Backend access password. Regenerated each startup unless you pass",
            "# --keep-password. Any username + this password may connect.",
            f"password = {password}",
        ]
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")
        return True
    except OSError as e:
        print(f"[redeye] warning: could not write password to {path}: {e}",
              file=sys.stderr)
        return False


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="REDEYE backend daemon (multiplayer)")
    ap.add_argument("--config", default=os.path.join(here, "config.cfg"))
    ap.add_argument("--mcp", default=None)
    ap.add_argument("--host", default=None)
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--keep-password", action="store_true",
                    help="(default now) reuse the existing [server]password")
    ap.add_argument("--rotate-password", action="store_true",
                    help="force a fresh password even if one is saved")
    args = ap.parse_args()

    st = S.load(args.config)
    if not os.path.isfile(args.config):
        st["_base_dir"] = here

    mcp_path = args.mcp or S.resolve(st, S.get(st, "paths", "mcp_config",
                                               "mcp_config.json"))
    try:
        with open(mcp_path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except FileNotFoundError:
        print(f"MCP config not found: {mcp_path}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as e:
        print(f"MCP config invalid JSON: {e}", file=sys.stderr)
        return 2

    config["_base_dir"] = os.path.dirname(os.path.abspath(mcp_path)) or "."
    config["settings"] = st
    config["config_path"] = args.config
    config["db_path"] = S.resolve(st, S.get(st, "paths", "db", "redeye.db"))

    # Password is stable across restarts: reuse the saved one, and only
    # generate (and persist) a new one when none exists or --rotate-password.
    existing = S.get(st, "server", "password", "")
    if existing and not args.rotate_password:
        password = existing
        reused = True
    else:
        password = _gen_password()
        persist_password(args.config, password)
        reused = False
    config["auth_password"] = password

    host = args.host or S.get(st, "server", "host", DEFAULT_HOST)
    port = args.port or int(S.get(st, "server", "port", str(DEFAULT_PORT)) or DEFAULT_PORT)

    print("=" * 56)
    print("  REDEYE backend -- multiplayer")
    print(f"  bind:     {host}:{port}")
    print(f"  password: {password}")
    print("  connect with any username + this password")
    if reused:
        print("  (reused from config.cfg; --rotate-password for a new one)")
    else:
        print("  (saved to [server]password in config.cfg)")
    print("=" * 56)

    daemon = RedeyeDaemon(config)
    try:
        daemon.serve(host, port)
    except KeyboardInterrupt:
        daemon.running = False
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
