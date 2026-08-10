"""Headless backend daemon -- everything REDEYE does that isn't rendering.

Owns the SQLite store, the crypto vault, the Bedrock/MCP worker bridge, and the
findings / PoC / Jira exporters. Speaks newline-delimited JSON over a local TCP
socket so front-ends (the Godot clients) can drive it. This replaces the
non-rendering half of the old pygame ``app.py``.

Multiplayer: many clients may connect at once; each is served on its own thread
and every authed client shares ONE session (one RED, one inventory, one map).
Worker events are broadcast to all; RPC replies go to the caller only. Auth is a
single startup password (any username): a client must send ``auth`` first.

Wire protocol -- one JSON object per line, UTF-8:

  client -> daemon
    {"cmd":"auth","user":"alice","password":".."}   # required first
    {"cmd":"list_models","profile":..,"region":..}
    {"cmd":"connect","profile":..,"region":..,"model_id":..,"model_label":..}
    {"cmd":"user_message","text":..}
    {"cmd":"call_tool","tool":..,"args":{..},"note":..}
    {"cmd":"shutdown"}
    {"rpc":"<name>","rid":N, ...args}      # DB / export calls; each gets a reply

  daemon -> client
    {"type":"auth_required"}                # sent on connect
    {"type":"auth_error","error":..}        # bad password (connection closed)
    {"type":"hello","user":..,"encrypted":bool,"jira":bool,"users":[..]}
    {"type":"Presence","user":..,"event":"join|leave","users":[..]}
    {"type":"ChatEcho","user":..,"text":..} # a directive someone issued
    {"type":"<EventName>", ...}             # streamed worker events (asdict)
    {"type":"rpc_result","rid":N,"ok":bool,...}

Only the front-end changed engines; this side is the same tested Python.
"""
from __future__ import annotations

import base64
import dataclasses
import json
import os
import secrets
import socket
import threading
import time

from . import advisor as ADV
from . import approvals as APPROVALS
from . import batch as BATCH
from . import bridge as B
from . import components as COMP
from . import correlate as CORR
from . import diffing as DIFF
from . import exporters
from . import gallery as GAL
from . import graph as GRAPH
from . import reporting as REPORT
from . import settings as S
from .bedrock import available_profiles
from .database import Store
from .scope import Scope
from .state import Host

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787


class _Client:
    """One connected front-end. Each runs in its own thread; `lock` serialises
    writes to this socket (the pump broadcasts from another thread)."""
    __slots__ = ("conn", "addr", "lock", "authed", "user", "alive")

    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        self.lock = threading.Lock()
        self.authed = False
        self.user = ""
        self.alive = True


class RedeyeDaemon:
    def __init__(self, config: dict):
        self.config = config
        db_path = config.get("db_path") or os.path.join(
            config.get("_base_dir", "."), "redeye.db")
        self.store = Store(db_path)
        self.db_lock = threading.Lock()
        self._apply_settings(config.get("settings"))
        self.jira_cfg = self._build_jira_cfg(config.get("settings"))

        # engagement scope -- shared with the worker (for tool enforcement) and
        # used to flag inventory assets in/out of scope.
        self.config_path = config.get("config_path", "")
        st0 = config.get("settings")
        entries = []
        if st0:
            raw = S.get(st0, "scope", "targets", "")
            entries = [t.strip() for t in raw.replace("\n", ",").split(",") if t.strip()]
        self.scope = Scope(entries)
        config["scope"] = self.scope        # worker reads this

        # correlation: configurable strong identity keys + a gen-based cache
        self.correlate_keys = CORR.DEFAULT_KEYS
        if st0:
            raw = S.get(st0, "correlate", "keys", "")
            ks = [k.strip() for k in raw.split(",") if k.strip()]
            if ks:
                self.correlate_keys = ks
        self._corr_lock = threading.Lock()
        self._corr_gen = 0
        self._corr_cache = None

        # approval gate: dangerous tools must be armed before they can run
        pats = None
        if st0:
            raw = S.get(st0, "approval", "dangerous", "")
            got = [p.strip() for p in raw.split(",") if p.strip()]
            if got:
                pats = got
        self.approvals = APPROVALS.Approvals(pats)
        config["approvals"] = self.approvals        # worker/mgr read this

        # engagement metadata for the report cover page
        self.engagement = {}
        self._server_status = {}      # server key -> status ("online"/...)
        if st0:
            for k in ("client", "tester", "window", "contact"):
                self.engagement[k] = S.get(st0, "engagement", k, "")

        self.bridge = B.Bridge()
        self.bridge.start(config)
        self._log("system", "REDEYE backend started")

        # multiplayer: every authed client shares one session. Auth = any
        # username + the single startup password (config["auth_password"]).
        self.password = str(config.get("auth_password", ""))
        self.clients: set = set()
        self.clients_lock = threading.Lock()
        self.running = True

        # tool preflight (nmap/nuclei/wapiti): detect, best-effort install,
        # report status so the UI can show a warning icon for missing tools.
        st = config.get("settings")
        self.auto_install = bool(st is None) or S.get_bool(st, "tools",
                                                           "auto_install", True)
        self.tool_lock = threading.Lock()
        self.tool_reports: list = []
        threading.Thread(target=self._preflight_tools, name="redeye-preflight",
                         daemon=True).start()

    # -- settings (ported from app.py) -------------------------------------
    def _apply_settings(self, st):
        if not st:
            return
        if S.get_bool(st, "vault", "encrypt", False):
            pw = os.environ.get("REDEYE_VAULT_PASSPHRASE") or S.get(
                st, "vault", "passphrase", "")
            if pw:
                with self.db_lock:
                    self.store.enable_encryption(pw)

    def _build_jira_cfg(self, st) -> dict:
        if not st:
            return {"base_url": "", "project": "SEC", "email": "", "token": ""}
        return {
            "base_url": S.get(st, "jira", "base_url", ""),
            "project": S.get(st, "jira", "project", "SEC") or "SEC",
            "email": S.get(st, "jira", "email", ""),
            "token": os.environ.get("REDEYE_JIRA_TOKEN")
            or S.get(st, "jira", "token", ""),
        }

    def _log(self, kind, text, detail=""):
        try:
            with self.db_lock:
                self.store.log_activity(kind, text, detail)
        except Exception:  # noqa: BLE001
            pass

    # -- outgoing framing ---------------------------------------------------
    def _send(self, client, obj: dict):
        line = (json.dumps(obj) + "\n").encode("utf-8")
        with client.lock:
            if not client.alive:
                return
            try:
                client.conn.sendall(line)
            except OSError:
                client.alive = False

    def _broadcast(self, obj: dict):
        with self.clients_lock:
            targets = [c for c in self.clients if c.authed and c.alive]
        for c in targets:
            self._send(c, obj)

    def _export_path(self, stem: str, ext: str) -> str:
        ts = time.strftime("%Y%m%d-%H%M%S")
        return os.path.join(self.store._export_dir(), f"{stem}_{ts}.{ext}")

    def _fetch_export(self, path: str) -> dict:
        """Return an exported file's bytes (base64) so a client can save it
        locally. Restricted to files under the exports directory."""
        root = os.path.realpath(self.store._export_dir())
        full = os.path.realpath(path if os.path.isabs(path)
                                else os.path.join(root, path))
        if not (full == root or full.startswith(root + os.sep)):
            raise ValueError("path outside exports directory")
        if not os.path.isfile(full):
            raise ValueError("no such export")
        with open(full, "rb") as f:
            data = f.read()
        return {"name": os.path.basename(full), "size": len(data),
                "b64": base64.b64encode(data).decode("ascii")}

    def _report_ctx(self) -> dict:
        corr = self._correlation()
        with self.db_lock:
            vault = [dict(r) for r in self.store.list_vault()]
            labels = self.store.list_labels()
            shots = self.store.list_screenshots(with_image=True)
        findings, assets = corr["findings"], corr["assets"]
        sev_counts = {}
        for f in findings:
            sv = str(f.get("severity", "")).upper()
            sev_counts[sv] = sev_counts.get(sv, 0) + 1
        return {
            "title": "REDEYE engagement report",
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "engagement": dict(self.engagement),
            "scope": self.scope.entries(), "sev_counts": sev_counts,
            "findings": findings, "assets": assets, "labels": labels,
            "screenshots": shots,
            "vault": [{"kind": v.get("kind"), "username": v.get("username"),
                       "scope": v.get("scope"), "status": v.get("status")}
                      for v in vault],
            "counts": {"findings_total": len(findings),
                       "assets_total": len(assets), "vault_total": len(vault)},
        }

    def _write_report_html(self) -> str:
        html = REPORT.html_report(self._report_ctx())
        path = self._export_path("report", "html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        self._log("export", "wrote HTML report", path)
        return path

    def _export_bundle(self) -> dict:
        ts = time.strftime("%Y%m%d-%H%M%S")
        base = os.path.join(self.store._export_dir(), f"engagement_{ts}")
        os.makedirs(base, exist_ok=True)
        files = []
        with self.db_lock:
            files.append(self.store.export_inventory_csv(
                os.path.join(base, "inventory.csv"))[0])
            files.append(self.store.export_findings_csv(
                os.path.join(base, "findings.csv"))[0])
            files.append(self.store.export_vault_csv(
                os.path.join(base, "credentials.csv"), reveal=False)[0])
            files.append(self.store.export_report_md(
                os.path.join(base, "report.md"))[0])
            labels = self.store.list_labels()
        corr = self._correlation()
        h1, r1 = REPORT.correlated_inventory_rows(corr["assets"])
        REPORT.write_csv(os.path.join(base, "inventory_correlated.csv"), h1, r1)
        files.append(os.path.join(base, "inventory_correlated.csv"))
        h2, r2 = REPORT.correlated_findings_rows(corr["findings"])
        REPORT.write_csv(os.path.join(base, "findings_correlated.csv"), h2, r2)
        files.append(os.path.join(base, "findings_correlated.csv"))
        hL, rL = REPORT.labels_rows(labels)
        REPORT.write_csv(os.path.join(base, "labels.csv"), hL, rL)
        files.append(os.path.join(base, "labels.csv"))
        html_path = os.path.join(base, "report.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(REPORT.html_report(self._report_ctx()))
        files.append(html_path)
        if REPORT.PDF_AVAILABLE:
            try:
                pdf_path = os.path.join(base, "report.pdf")
                with open(pdf_path, "wb") as f:
                    f.write(REPORT.pdf_report(self._report_ctx()))
                files.append(pdf_path)
            except Exception:  # noqa: BLE001
                pass
        self._log("export", f"wrote engagement bundle ({len(files)} files)", base)
        return {"dir": base, "files": [os.path.basename(f) for f in files]}

    def _label_endpoints(self, label: str) -> list:
        if not label:
            return []
        with self.db_lock:
            members = self.store.label_members(label)
            rows = {r["id"]: dict(r) for r in self.store.list_assets()}
        eps = []
        for mem in members:
            row = rows.get(mem["asset_id"])
            if row:
                eps.append(BATCH.endpoint_from_row(row, mem["port"]))
        return eps

    def _roster(self) -> list:
        with self.clients_lock:
            return sorted({c.user for c in self.clients if c.authed})

    # -- correlation (read-time, cached by generation) ----------------------
    def _bump_corr(self):
        with self._corr_lock:
            self._corr_gen += 1

    def _correlation(self) -> dict:
        with self._corr_lock:
            if self._corr_cache and self._corr_cache.get("gen") == self._corr_gen:
                return self._corr_cache
            gen = self._corr_gen
        with self.db_lock:
            arows = [dict(r) for r in self.store.list_assets()]
            frows = [dict(r) for r in self.store.list_findings()]
            links = self.store.list_correlation_links()
        merges = [(l["a_id"], l["b_id"]) for l in links if l["kind"] == "merge"]
        dismissed = [frozenset({l["a_id"], l["b_id"]}) for l in links
                     if l["kind"] == "dismiss"]
        res = CORR.correlate_assets(arows, self.correlate_keys, merges, dismissed)
        findings = CORR.correlate_findings(frows, res["assets"])
        out = {"gen": gen, "assets": res["assets"],
               "suggestions": res["suggestions"], "findings": findings}
        with self._corr_lock:
            self._corr_cache = out
        return out

    # -- tool preflight -----------------------------------------------------
    def _preflight_tools(self, stream=False, do_install=None):
        from . import toolcheck as TC
        do_install = self.auto_install if do_install is None else do_install
        reports = []
        for k in list(TC.TOOLS):
            present = TC._present(TC.TOOLS[k]["bin"])
            if not present and do_install:
                if stream:
                    self._broadcast({"type": "ToolStatus",
                                     **TC._report(k, "installing")})
                rep = TC.install(k)
            elif present:
                rep = TC._report(k, "ok")
            else:
                rep = TC.check(k)
            reports.append(rep)
            self._broadcast({"type": "ToolStatus", **rep})
            if rep["status"] in ("mock", "error"):
                self._log("system", f"tool {rep['name']}: {rep['status']}",
                          rep.get("detail", ""))
        with self.tool_lock:
            self.tool_reports = reports
        return reports

    @staticmethod
    def _event_json(ev) -> dict:
        d = dataclasses.asdict(ev)
        d["type"] = type(ev).__name__
        return d

    # -- worker event -> DB side effects (ported from app.apply_event) ------
    def _apply_event_db(self, ev):
        try:
            if isinstance(ev, B.ServerStatus):
                self._server_status[ev.key] = ev.status
            if isinstance(ev, (B.HostUpsert, B.FindingUpsert)):
                self._bump_corr()
            if isinstance(ev, B.ScreenshotUpsert):
                with self.db_lock:
                    self.store.upsert_screenshot(ev.url, ev.image_b64,
                                                 ev.asset, ev.title,
                                                 ev.status, ev.phash)
                self._broadcast({"type": "ScreenshotCaptured", "url": ev.url,
                                 "asset": ev.asset})
                return
            if isinstance(ev, B.HostUpsert):
                insc = self.scope.matches_asset(ev.ip, ev.hostname)
                with self.db_lock:
                    exists = self.store.conn.execute(
                        "SELECT 1 FROM inventory WHERE id=?", (ev.id,)).fetchone()
                    self.store.upsert_asset(Host(
                        id=ev.id, label=ev.label, source=ev.source, kind=ev.kind,
                        ip=ev.ip, hostname=ev.hostname, os=ev.os, status=ev.status,
                        ports=ev.ports, meta=ev.meta, color=tuple(ev.color)),
                        in_scope=insc)
                if not exists:
                    self._log("discovery", f"{ev.kind} {ev.label}",
                              f"{ev.ip or ev.hostname} via {ev.source}")
            elif isinstance(ev, B.FindingUpsert):
                with self.db_lock:
                    fid = self.store.upsert_scan_finding(
                        ev.dedupe, title=ev.title, severity=ev.severity,
                        hosts=ev.hosts, description=ev.description,
                        recommendation=ev.recommendation,
                        source=f"scan:{ev.source}" if ev.source else "scan")
                self._log("finding", f"{ev.severity} {ev.title}",
                          f"#{fid} {ev.hosts}")
            elif isinstance(ev, B.VaultUpsert):
                with self.db_lock:
                    self.store.upsert_discovered_secret(
                        kind=ev.kind, label=ev.label, username=ev.username,
                        secret=ev.secret, scope=ev.scope,
                        source=f"scan:{ev.source}" if ev.source else "scan",
                        notes=ev.notes)
                self._log("vault", f"captured {ev.kind} "
                          f"{ev.username or ev.label or ev.kind}", ev.scope)
            elif isinstance(ev, B.ToolStart):
                self._log("command", f"{ev.server}.{ev.name}" if ev.server
                          else ev.name, _fmt_args(ev.args))
            elif isinstance(ev, B.Connected):
                self._log("system",
                          f"link established // {ev.model_label or ev.model_id}")
            elif isinstance(ev, B.Error):
                self._log("error", ev.text[:200])
        except Exception:  # noqa: BLE001
            pass

    # -- the event pump: bridge -> DB + socket -----------------------------
    def _pump(self):
        import time
        while self.running:
            evs = self.bridge.drain()
            for ev in evs:
                self._apply_event_db(ev)
                if not isinstance(ev, B.ScreenshotUpsert):
                    self._broadcast(self._event_json(ev))
            if not evs:
                time.sleep(0.02)

    # -- incoming command / rpc dispatch -----------------------------------
    def _handle_line(self, client, line: str):
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            return
        if not client.authed:
            self._try_auth(client, msg)
            return
        if "cmd" in msg:
            self._handle_command(client, msg)
        elif "rpc" in msg:
            self._handle_rpc(client, msg)

    def _handle_command(self, client, m):
        c = m.get("cmd")
        if c == "list_models":
            self.bridge.send(B.ListModels(m.get("profile", ""), m.get("region", "")))
        elif c == "connect":
            self._log("system", f"{client.user} opened a link")
            self.bridge.send(B.Connect(m.get("profile", ""), m.get("region", ""),
                                       m.get("model_id", ""),
                                       m.get("model_label", "")))
        elif c == "user_message":
            text = m.get("text", "")
            # echo the directive to every operator so the session is shared
            self._broadcast({"type": "ChatEcho", "user": client.user, "text": text})
            self._log("command", f"[{client.user}] {text[:180]}", "operator directive")
            self.bridge.send(B.UserMessage(text))
        elif c == "call_tool":
            self.bridge.send(B.CallToolDirect(m.get("tool", ""),
                                              m.get("args", {}), m.get("note", "")))
        elif c == "recheck_tools":
            do_install = bool(m.get("install", True))
            threading.Thread(target=self._preflight_tools,
                             kwargs={"stream": True, "do_install": do_install},
                             name="redeye-recheck", daemon=True).start()
        elif c == "batch_run":
            self._start_batch(client, m)
        elif c == "shutdown":
            self._log("system", f"{client.user} requested shutdown")
            self.running = False

    def _target_key_for(self, tool) -> str:
        # tools that take a URL rather than a bare host:port
        tl = str(tool).lower()
        if any(k in tl for k in ("probe", "screenshot", "witness",
                                 "fingerprint", "httpx")):
            return "url"
        return "target"

    def _recommendations(self) -> list:
        corr = self._correlation()
        with self.db_lock:
            assets = [dict(r) for r in self.store.list_assets()]
            findings = [dict(r) for r in self.store.list_findings()]
            vault = [dict(r) for r in self.store.list_vault()]
            labels = self.store.list_labels()
            snaps = self.store.list_snapshots()
            shots = self.store.list_screenshots(with_image=False)
        web_ports = {80, 443, 8080, 8443, 8000, 8888, 8081}

        def _ports(a):
            try:
                return json.loads(a.get("ports_json") or "[]")
            except Exception:  # noqa: BLE001
                return []

        def is_web(a):
            for p in _ports(a):
                if p.get("state") == "open" and (
                        p.get("port") in web_ports or
                        "http" in str(p.get("service", "")).lower()):
                    return True
            return False

        def host_of(a):
            return str(a.get("ip") or a.get("hostname") or a.get("label") or "").lower()

        web_hosts = [a for a in assets if is_web(a)]
        shot_hosts = {str(s.get("asset", "")).lower() for s in shots}
        web_without_shot = sum(1 for a in web_hosts if host_of(a) not in shot_hosts)
        fingerprinted = 0
        for a in assets:
            try:
                meta = json.loads(a.get("meta_json") or "{}")
            except Exception:  # noqa: BLE001
                meta = {}
            if meta.get("tech") or meta.get("title"):
                fingerprinted += 1
        comps = COMP.build_components(assets, findings)
        st = {
            "scope_set": len(self.scope.entries()) > 0,
            "servers_online": sum(1 for v in self._server_status.values()
                                  if v == "online"),
            "assets": len(assets),
            "open_hosts": sum(1 for a in assets if a.get("open_count")),
            "web_hosts": len(web_hosts),
            "web_without_shot": web_without_shot,
            "screenshots": len(shots),
            "fingerprinted": fingerprinted,
            "findings": len(findings),
            "vault_untested": sum(1 for v in vault
                                  if str(v.get("status", "")) in ("untested", "")),
            "labels": len(labels),
            "snapshots": len(snaps),
            "suggestions": len(corr.get("suggestions", [])),
            "components": len(comps),
            "versioned": sum(1 for c in comps if c.get("version")),
            "flagged": sum(1 for c in comps if c.get("vuln")),
        }
        return ADV.recommend(st)

    def _gallery(self, sort: str, label: str, query: str) -> list:
        with self.db_lock:
            shots = self.store.list_screenshots(with_image=True)
            labelmap = self.store.asset_label_map()      # asset_id -> [labels]
            assets = [dict(r) for r in self.store.list_assets()]
        idx = {}
        for a in assets:
            for tok in (a.get("ip"), a.get("hostname"), a.get("label")):
                if tok:
                    idx[str(tok).lower()] = a["id"]
        for s in shots:
            host = str(s.get("asset", "")).lower()
            aid = idx.get(host)
            if aid is None:
                for tok, i2 in idx.items():
                    if tok and (tok in host or host in tok):
                        aid = i2
                        break
            s["labels"] = labelmap.get(aid, []) if aid else []
            s["image_b64"] = s.pop("image", "")
        shots = GAL.filter_screenshots(shots, label, query)
        return GAL.sort_screenshots(shots, sort)

    def _screenshot_for(self, key: str):
        """Best-effort match of an asset host/label/ip to a stored screenshot."""
        key = (key or "").strip().lower()
        if not key:
            return None
        with self.db_lock:
            shots = self.store.list_screenshots(with_image=True)
        for s in shots:
            asset = str(s.get("asset", "")).lower()
            url = str(s.get("url", "")).lower()
            if key == asset or (asset and asset in key) or key in url:
                return {"url": s.get("url", ""), "title": s.get("title", ""),
                        "image_b64": s.get("image", "")}
        return None

    def _start_batch(self, client, m):
        args = dict(m.get("args", {}))
        # optional: inject a vault credential (username/password/secret)
        cid = m.get("cred_id")
        if cid:
            try:
                with self.db_lock:
                    row = next((dict(r) for r in self.store.list_vault()
                                if int(r["id"]) == int(cid)), None)
                    secret = self.store.reveal_secret(int(cid))
                if row:
                    args.setdefault("username", row.get("username", ""))
                    args.setdefault("password", secret)
                    args.setdefault("secret", secret)
            except Exception:  # noqa: BLE001
                pass
        # build the step playbook: one or more tools, run per endpoint
        tools = m.get("tools") or ([m["tool"]] if m.get("tool") else [])
        tools = [str(t).strip() for t in tools if str(t).strip()]
        default_key = m.get("target_key")
        steps = []
        for t in tools:
            tk = default_key or self._target_key_for(t)
            steps.append({"tool": t, "target_key": tk, "args": dict(args)})
        # expand targets from a label or a live filter query
        label = m.get("label", "")
        if label:
            eps = self._label_endpoints(label)
        else:
            with self.db_lock:
                rows = [dict(r) for r in self.store.list_assets()]
            eps = BATCH.endpoints_for_rows(rows, m.get("query", ""),
                                           m.get("ports", "web"))
        # only run against in-scope endpoints (mgr.call also enforces per target)
        eps = [e for e in eps
               if self.scope.matches_asset(e.get("ip"), e.get("hostname"))]
        if not eps or not steps:
            self._send(client, {"type": "BatchEnd",
                                "tool": ",".join(tools), "total": 0,
                                "ok": 0, "fail": 0, "label": label,
                                "note": "nothing to run (no in-scope endpoints "
                                        "or no tool selected)"})
            return
        self._log("command",
                  f"[{client.user}] batch {','.join(tools)} x{len(eps)}",
                  label or m.get("query", ""))
        self.bridge.send(B.BatchRun(steps, eps, label or m.get("query", "")))

    def _handle_rpc(self, client, m):
        name = m.get("rpc")
        rid = m.get("rid")
        try:
            result = self._rpc(name, m)
            self._send(client, {"type": "rpc_result", "rid": rid, "ok": True,
                                "result": result})
        except Exception as e:  # noqa: BLE001
            self._send(client, {"type": "rpc_result", "rid": rid, "ok": False,
                                "error": str(e)})

    def _rpc(self, name, m):
        s = self.store
        if name == "tool_status":
            with self.tool_lock:
                return list(self.tool_reports)
        if name == "get_scope":
            return self.scope.entries()
        if name == "set_scope":
            entries = m.get("entries", [])
            if isinstance(entries, str):
                entries = [t.strip() for t in entries.replace("\n", ",").split(",")]
            self.scope.set(entries)
            with self.db_lock:
                self.store.recompute_scope(self.scope)
            self._bump_corr()
            if self.config_path:
                S.write_value(self.config_path, "scope", "targets",
                              ", ".join(self.scope.entries()))
            self._log("system", "scope updated",
                      ", ".join(self.scope.entries()) or "(unrestricted)")
            self._broadcast({"type": "ScopeUpdated", "entries": self.scope.entries()})
            return self.scope.entries()
        # -- correlation (read-time merged view) --
        if name == "correlated_assets":
            return self._correlation()["assets"]
        if name == "correlated_findings":
            return self._correlation()["findings"]
        if name == "correlation_suggestions":
            return self._correlation()["suggestions"]
        if name == "merge_assets":
            ids = m.get("ids") or [m.get("a"), m.get("b")]
            ids = [str(x) for x in ids if x]
            with self.db_lock:
                for other in ids[1:]:
                    self.store.add_correlation_link("merge", ids[0], other)
            self._bump_corr()
            self._log("correlation", f"merged {len(ids)} assets", ", ".join(ids))
            self._broadcast({"type": "CorrelationUpdated"})
            return True
        if name == "unmerge_assets":
            with self.db_lock:
                self.store.delete_correlation_link("merge", str(m.get("a", "")),
                                                   str(m.get("b", "")))
            self._bump_corr()
            self._broadcast({"type": "CorrelationUpdated"})
            return True
        if name == "dismiss_suggestion":
            with self.db_lock:
                self.store.add_correlation_link("dismiss", str(m.get("a", "")),
                                                str(m.get("b", "")))
            self._bump_corr()
            self._broadcast({"type": "CorrelationUpdated"})
            return True
        # -- labels + batch endpoint preview --
        if name == "list_labels":
            with self.db_lock:
                return self.store.list_labels()
        if name == "label_endpoints":
            return self._label_endpoints(m.get("label", ""))
        if name == "filter_endpoints":
            with self.db_lock:
                rows = [dict(r) for r in self.store.list_assets()]
            return BATCH.endpoints_for_rows(rows, m.get("query", ""),
                                            m.get("ports", "web"))
        if name == "label_from_query":
            label = m.get("label", "").strip()
            if not label:
                raise ValueError("label name required")
            with self.db_lock:
                rows = [dict(r) for r in self.store.list_assets()]
            eps = BATCH.endpoints_for_rows(rows, m.get("query", ""),
                                           m.get("ports", "web"))
            with self.db_lock:
                for ep in eps:
                    self.store.add_label_member(label, ep["asset_id"],
                                                ep["port"] if ep["port"] else -1)
            self._log("labels", f"labelled {len(eps)} endpoints as '{label}'",
                      m.get("query", ""))
            self._broadcast({"type": "LabelUpdated", "label": label})
            return {"label": label, "added": len(eps)}
        if name == "auto_label":
            with self.db_lock:
                rows = [dict(r) for r in self.store.list_assets()]
            groups = BATCH.auto_group(rows, m.get("ports", "web"),
                                      m.get("min", 2))
            with self.db_lock:
                for g in groups:
                    for ep in g["endpoints"]:
                        self.store.add_label_member(
                            g["label"], ep["asset_id"],
                            ep["port"] if ep["port"] else -1)
            summary = [{"label": g["label"], "count": g["count"]} for g in groups]
            self._log("labels", f"auto-labelled {len(groups)} service group(s)",
                      ", ".join(g["label"] for g in groups))
            self._broadcast({"type": "LabelUpdated", "label": ""})
            return summary
        if name == "label_like":
            with self.db_lock:
                rows = [dict(r) for r in self.store.list_assets()]
            sig, eps, default_label = BATCH.endpoints_like(
                rows, m.get("asset_id", ""), m.get("port"))
            if not eps:
                return {"label": "", "added": 0, "signature": sig}
            label = (m.get("label") or default_label).strip()
            with self.db_lock:
                for ep in eps:
                    self.store.add_label_member(label, ep["asset_id"],
                                                ep["port"] if ep["port"] else -1)
            self._log("labels", f"labelled {len(eps)} endpoints like {sig}",
                      label)
            self._broadcast({"type": "LabelUpdated", "label": label})
            return {"label": label, "added": len(eps), "signature": sig}
        if name == "add_label_member":
            with self.db_lock:
                self.store.add_label_member(m["label"], m["asset_id"],
                                            m.get("port", -1))
            self._broadcast({"type": "LabelUpdated", "label": m["label"]})
            return True
        if name == "remove_label":
            with self.db_lock:
                self.store.remove_label(m["label"])
            self._broadcast({"type": "LabelUpdated", "label": m["label"]})
            return True
        if name == "remove_label_member":
            with self.db_lock:
                self.store.remove_label_member(m["label"], m["asset_id"],
                                               m.get("port", -1))
            self._broadcast({"type": "LabelUpdated", "label": m["label"]})
            return True
        # -- richer exports (correlation/scope aware) --
        if name == "export_report_html":
            return {"path": self._write_report_html()}
        if name == "export_report_pdf":
            if not REPORT.PDF_AVAILABLE:
                return {"error": "PDF support not installed on the backend "
                                 "(pip install fpdf2)"}
            path = self._export_path("report", "pdf")
            with open(path, "wb") as f:
                f.write(REPORT.pdf_report(self._report_ctx()))
            self._log("export", "wrote PDF report", path)
            return {"path": path}
        if name == "export_correlated_inventory_csv":
            corr = self._correlation()
            header, rows = REPORT.correlated_inventory_rows(corr["assets"])
            path = self._export_path("inventory_correlated", "csv")
            REPORT.write_csv(path, header, rows)
            return [path, len(rows)]
        if name == "export_correlated_findings_csv":
            corr = self._correlation()
            header, rows = REPORT.correlated_findings_rows(corr["findings"])
            path = self._export_path("findings_correlated", "csv")
            REPORT.write_csv(path, header, rows)
            return [path, len(rows)]
        if name == "export_labels_csv":
            with self.db_lock:
                labels = self.store.list_labels()
            header, rows = REPORT.labels_rows(labels)
            path = self._export_path("labels", "csv")
            REPORT.write_csv(path, header, rows)
            return [path, len(rows)]
        if name == "export_bundle":
            return self._export_bundle()
        # -- approval gate --
        if name == "list_approvals":
            return self.approvals.status()
        if name == "arm_tool":
            self.approvals.arm(str(m.get("tool", "")), bool(m.get("on", True)))
            self._log("approval",
                      f"{'armed' if m.get('on', True) else 'disarmed'} {m.get('tool','')}")
            self._broadcast({"type": "ApprovalUpdated",
                             **self.approvals.status()})
            return self.approvals.status()
        # -- scan diffing --
        if name == "take_snapshot":
            with self.db_lock:
                snap = DIFF.make_snapshot(
                    [dict(r) for r in self.store.list_assets()],
                    [dict(r) for r in self.store.list_findings()])
                sid = self.store.add_snapshot(str(m.get("label", "")), snap)
            self._log("snapshot", f"took snapshot #{sid}", m.get("label", ""))
            self._broadcast({"type": "SnapshotUpdated"})
            return {"id": sid}
        if name == "list_snapshots":
            with self.db_lock:
                return self.store.list_snapshots()
        if name == "delete_snapshot":
            with self.db_lock:
                self.store.delete_snapshot(int(m["id"]))
            self._broadcast({"type": "SnapshotUpdated"})
            return True
        if name == "diff_snapshot":
            with self.db_lock:
                old = self.store.get_snapshot(int(m["id"]))
                cur = DIFF.make_snapshot(
                    [dict(r) for r in self.store.list_assets()],
                    [dict(r) for r in self.store.list_findings()])
            if old is None:
                raise ValueError("no such snapshot")
            return DIFF.diff(old, cur)
        # -- attack graph --
        if name == "attack_graph":
            corr = self._correlation()
            with self.db_lock:
                vault = [dict(r) for r in self.store.list_vault()]
            return GRAPH.build_graph(corr["assets"], corr["findings"], vault)
        # -- engagement metadata (report cover) --
        if name == "get_engagement":
            return dict(self.engagement)
        if name == "set_engagement":
            for k in ("client", "tester", "window", "contact"):
                if k in m:
                    self.engagement[k] = str(m.get(k, ""))
                    if self.config_path:
                        S.write_value(self.config_path, "engagement", k,
                                      self.engagement[k])
            self._broadcast({"type": "EngagementUpdated", **self.engagement})
            return dict(self.engagement)
        # -- download an export over the socket --
        if name == "fetch_export":
            return self._fetch_export(str(m.get("path", "")))
        if name == "get_screenshot":
            return self._screenshot_for(str(m.get("host") or m.get("url") or "")) or {}
        if name == "gallery":
            return self._gallery(str(m.get("sort", "recent")),
                                 str(m.get("label", "")), str(m.get("query", "")))
        if name == "recommendations":
            return self._recommendations()
        if name == "components":
            with self.db_lock:
                assets = [dict(r) for r in self.store.list_assets()]
                findings = [dict(r) for r in self.store.list_findings()]
            comps = COMP.build_components(assets, findings)
            return COMP.search_components(comps, str(m.get("query", "")))
        rows = lambda rs: [dict(r) for r in rs]  # noqa: E731
        with self.db_lock:
            if name == "available_profiles":
                return available_profiles()
            if name == "encryption_on":
                return s.encryption_on()
            # inventory
            if name == "list_assets":
                return rows(s.list_assets())
            if name == "set_asset_notes":
                s.set_asset_notes(m["id"], m.get("notes", "")); return True
            if name == "set_asset_scope":
                s.set_asset_scope(m["id"], bool(m.get("in_scope", True))); return True
            if name == "delete_asset":
                s.delete_asset(m["id"]); return True
            # findings
            if name == "list_findings":
                return rows(s.list_findings())
            if name == "get_finding":
                r = s.get_finding(m["id"]); return dict(r) if r else None
            if name == "add_finding":
                return s.add_finding(**_pick(m, ("title", "severity", "status",
                    "hosts", "description", "recommendation", "source")))
            if name == "list_screenshots":
                return s.list_screenshots(with_image=False)
            if name == "update_finding":
                s.update_finding(m["id"], **_pick(m, ("title", "severity", "status",
                    "hosts", "description", "recommendation", "cvss", "cwe",
                    "evidence"))); return True
            if name == "delete_finding":
                s.delete_finding(m["id"]); return True
            if name == "set_finding_ticket":
                s.set_finding_ticket(m["id"], m.get("ticket", "")); return True
            # vault
            if name == "list_vault":
                return rows(s.list_vault())
            if name == "reveal_secret":
                return s.reveal_secret(m["id"])
            if name == "add_credential":
                return s.add_credential(**_pick(m, ("kind", "label", "username",
                    "secret", "scope", "notes", "source")))
            if name == "update_credential":
                s.update_credential(m["id"], **_pick(m, ("kind", "label",
                    "username", "secret", "scope", "notes"))); return True
            if name == "set_cred_status":
                s.set_cred_status(m["id"], m.get("status", "untested")); return True
            if name == "delete_credential":
                s.delete_credential(m["id"]); return True
            # activity
            if name == "list_activity":
                return rows(s.list_activity(m.get("limit", 1000), m.get("kind")))
            if name == "clear_activity":
                s.clear_activity(); return True
            # exports
            if name == "export_inventory_csv":
                return s.export_inventory_csv()
            if name == "export_findings_csv":
                return s.export_findings_csv()
            if name == "export_vault_csv":
                return s.export_vault_csv(reveal=bool(m.get("reveal", False)))
            if name == "export_activity_csv":
                return s.export_activity_csv()
            if name == "export_report_md":
                return s.export_report_md()
            if name == "export_python_poc":
                r = s.get_finding(m["id"])
                if not r:
                    raise ValueError("no such finding")
                return exporters.write_python_poc(s._export_dir(), dict(r))
            if name == "jira_ticket":
                r = s.get_finding(m["id"])
                if not r:
                    raise ValueError("no such finding")
                f = dict(r)
                if exporters.jira_configured(self.jira_cfg):
                    ok, res = exporters.jira_create(f, self.jira_cfg)
                    if ok:
                        s.set_finding_ticket(f["id"], res)
                        return {"mode": "created", "key": res,
                                "url": exporters.browse_url(self.jira_cfg, res)}
                path = exporters.write_jira_payload(
                    s._export_dir(), f, self.jira_cfg.get("project", "SEC"))
                s.set_finding_ticket(f["id"], f"file:{path}")
                return {"mode": "file", "path": path}
        raise ValueError(f"unknown rpc: {name}")

    # -- socket server ------------------------------------------------------
    def serve(self, host=DEFAULT_HOST, port=DEFAULT_PORT):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(16)
        srv.settimeout(0.5)
        threading.Thread(target=self._pump, name="redeye-pump",
                         daemon=True).start()
        print(f"[redeye] backend listening on {host}:{port} "
              f"(multiplayer; {'auth on' if self.password else 'NO PASSWORD SET'})")
        try:
            while self.running:
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                conn.settimeout(0.5)
                client = _Client(conn, addr)
                with self.clients_lock:
                    self.clients.add(client)
                threading.Thread(target=self._client_loop, args=(client,),
                                 name=f"redeye-client-{addr[1]}",
                                 daemon=True).start()
        finally:
            self.running = False
            self.bridge.stop()
            with self.clients_lock:
                clients = list(self.clients)
            for c in clients:
                try:
                    c.conn.close()
                except OSError:
                    pass
            with self.db_lock:
                self.store.close()
            srv.close()

    def _client_loop(self, client):
        # ask for credentials up front
        self._send(client, {"type": "auth_required"})
        buf = b""
        try:
            while self.running and client.alive:
                try:
                    chunk = client.conn.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line.strip():
                        self._handle_line(client, line.decode("utf-8", "replace"))
        finally:
            self._drop(client)

    def _try_auth(self, client, msg):
        if msg.get("cmd") != "auth" and "auth" not in msg:
            self._send(client, {"type": "auth_required"})
            return
        block = msg.get("auth") if isinstance(msg.get("auth"), dict) else msg
        user = str(block.get("user", "") or "operator").strip()[:32] or "operator"
        pw = str(block.get("password", ""))
        ok = bool(self.password) and secrets.compare_digest(pw, self.password)
        if not ok:
            # keep the connection open so the operator can just re-enter the key;
            # closing here would surface to the client as a dropped link.
            self._send(client, {"type": "auth_error", "error": "invalid credentials"})
            return
        client.authed = True
        client.user = user
        with self.db_lock:
            enc = self.store.encryption_on()
        with self.tool_lock:
            tools = list(self.tool_reports)
        self._log("system", f"{user} connected")
        self._send(client, {"type": "hello", "user": user, "encrypted": enc,
                            "jira": exporters.jira_configured(self.jira_cfg),
                            "users": self._roster(), "tools": tools,
                            "scope": self.scope.entries()})
        for rep in tools:
            self._send(client, {"type": "ToolStatus", **rep})
        self._broadcast({"type": "Presence", "user": user, "event": "join",
                         "users": self._roster()})

    def _drop(self, client):
        with self.clients_lock:
            self.clients.discard(client)
        client.alive = False
        try:
            client.conn.close()
        except OSError:
            pass
        if client.authed:
            self._log("system", f"{client.user} disconnected")
            self._broadcast({"type": "Presence", "user": client.user,
                             "event": "leave", "users": self._roster()})


def _pick(m, keys):
    return {k: m[k] for k in keys if k in m}


def _fmt_args(args) -> str:
    if not isinstance(args, dict) or not args:
        return ""
    parts = []
    for k, v in args.items():
        sv = str(v)
        parts.append(f"{k}={sv[:38] + '..' if len(sv) > 40 else sv}")
    return ", ".join(parts)
