"""Persistence for REDEYE: an inventory database and a security-findings
database, backed by a single local SQLite file (stdlib, no extra deps).

- inventory: assets discovered on the map (auto-populated from scans) plus
  manual notes. One row per node id.
- findings: manually authored security findings (title / description /
  recommendation / severity / hosts) edited from the Findings view.

Both export to CSV. All access is serialised behind the daemon's DB lock,
so the default sqlite threading rules are fine.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import sqlite3
import time

from . import crypto_vault

# -- severity + status vocabularies -----------------------------------------
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_COLORS = {
    "CRITICAL": (255, 60, 60),
    "HIGH":     (255, 120, 60),
    "MEDIUM":   (255, 190, 70),
    "LOW":      (120, 200, 130),
    "INFO":     (120, 180, 255),
}
STATUSES = ["open", "triage", "confirmed", "remediated", "closed"]
STATUS_COLORS = {
    "open":       (255, 90, 70),
    "triage":     (255, 190, 70),
    "confirmed":  (255, 60, 60),
    "remediated": (120, 200, 130),
    "closed":     (120, 130, 140),
}


# -- vault vocabularies ------------------------------------------------------
VAULT_KINDS = ["credential", "secret", "token", "api-key", "hash"]
VAULT_STATUSES = ["untested", "valid", "invalid"]
VAULT_STATUS_COLORS = {
    "untested": (200, 190, 120),
    "valid":    (90, 220, 130),
    "invalid":  (200, 80, 80),
}


def vault_status_color(status: str):
    return VAULT_STATUS_COLORS.get((status or "").lower(), (200, 200, 200))


def severity_color(sev: str):
    return SEVERITY_COLORS.get((sev or "").upper(), (200, 200, 200))


def status_color(status: str):
    return STATUS_COLORS.get((status or "").lower(), (200, 200, 200))


class Store:
    def __init__(self, path: str):
        self.path = path
        # check_same_thread=False lets the backend daemon touch the DB from its
        # reader and writer threads; callers serialise access with a lock.
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.cipher = None            # set by enable_encryption()
        self._init_schema()

    def _init_schema(self):
        c = self.conn
        c.execute("""
            CREATE TABLE IF NOT EXISTS inventory (
                id          TEXT PRIMARY KEY,
                label       TEXT,
                kind        TEXT,
                source      TEXT,
                ip          TEXT,
                hostname    TEXT,
                os          TEXT,
                status      TEXT,
                open_count  INTEGER DEFAULT 0,
                ports_json  TEXT DEFAULT '[]',
                meta_json   TEXT DEFAULT '{}',
                notes       TEXT DEFAULT '',
                first_seen  REAL,
                last_seen   REAL
            )""")
        c.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                title          TEXT NOT NULL DEFAULT 'Untitled finding',
                severity       TEXT NOT NULL DEFAULT 'MEDIUM',
                status         TEXT NOT NULL DEFAULT 'open',
                hosts          TEXT DEFAULT '',
                description    TEXT DEFAULT '',
                recommendation TEXT DEFAULT '',
                created        REAL,
                updated        REAL
            )""")
        c.execute("""
            CREATE TABLE IF NOT EXISTS vault (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                kind        TEXT DEFAULT 'credential',
                label       TEXT DEFAULT '',
                username    TEXT DEFAULT '',
                secret      TEXT DEFAULT '',
                scope       TEXT DEFAULT '',
                source      TEXT DEFAULT 'manual',
                status      TEXT DEFAULT 'untested',
                notes       TEXT DEFAULT '',
                dedupe      TEXT UNIQUE,
                created     REAL,
                updated     REAL,
                last_tried  REAL
            )""")
        c.execute("""
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT
            )""")
        c.execute("""
            CREATE TABLE IF NOT EXISTS activity (
                id     INTEGER PRIMARY KEY AUTOINCREMENT,
                ts     REAL,
                kind   TEXT DEFAULT 'system',
                text   TEXT DEFAULT '',
                detail TEXT DEFAULT ''
            )""")
        c.execute("""
            CREATE TABLE IF NOT EXISTS correlation_links (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                kind    TEXT DEFAULT 'merge',   -- 'merge' | 'dismiss'
                a_id    TEXT,
                b_id    TEXT,
                created REAL
            )""")
        c.execute("""
            CREATE TABLE IF NOT EXISTS label_members (
                label    TEXT,
                asset_id TEXT,
                port     INTEGER DEFAULT -1,     -- -1 = whole host
                created  REAL,
                UNIQUE(label, asset_id, port)
            )""")
        c.execute("""
            CREATE TABLE IF NOT EXISTS snapshots (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                ts      REAL,
                label   TEXT DEFAULT '',
                data    TEXT
            )""")
        c.execute("""
            CREATE TABLE IF NOT EXISTS integrations (
                id      TEXT PRIMARY KEY,
                tool    TEXT,
                name    TEXT,
                config  TEXT DEFAULT '{}',   -- JSON: field -> value or vault:<id>
                created REAL
            )""")
        c.execute("""
            CREATE TABLE IF NOT EXISTS screenshots (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                url     TEXT,
                asset   TEXT DEFAULT '',
                title   TEXT DEFAULT '',
                image   TEXT,          -- base64 PNG
                status  INTEGER DEFAULT 0,
                phash   TEXT DEFAULT '',
                created REAL,
                UNIQUE(url)
            )""")
        # migrations: scan-sourced findings need source + dedupe; tickets need a ref
        self._ensure_column("findings", "source", "TEXT DEFAULT 'manual'")
        self._ensure_column("findings", "dedupe", "TEXT")
        self._ensure_column("findings", "ticket", "TEXT DEFAULT ''")
        # inventory carries a binary in/out-of-scope flag (default in-scope)
        self._ensure_column("inventory", "in_scope", "INTEGER DEFAULT 1")
        # findings gain CVSS / CWE / evidence for a richer report
        self._ensure_column("findings", "cvss", "TEXT DEFAULT ''")
        self._ensure_column("findings", "cwe", "TEXT DEFAULT ''")
        self._ensure_column("findings", "evidence", "TEXT DEFAULT ''")
        c.commit()

    def _ensure_column(self, table: str, col: str, decl: str):
        cols = [r["name"] for r in
                self.conn.execute(f"PRAGMA table_info({table})").fetchall()]
        if col not in cols:
            self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")

    # -- meta / encryption --------------------------------------------------
    def _meta_get(self, key: str):
        r = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return r["value"] if r else None

    def _meta_set(self, key: str, value: str):
        self.conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
        self.conn.commit()

    def enable_encryption(self, passphrase: str) -> tuple[bool, str]:
        """Turn on at-rest secret encryption. Returns (ok, message).

        On first use it stores a random salt + a verifier token. On later runs
        it checks the passphrase against the verifier so a wrong passphrase is
        reported instead of silently corrupting reads."""
        if not passphrase:
            return False, "no passphrase"
        if not crypto_vault.available():
            return False, "cryptography package unavailable"
        salt_hex = self._meta_get("vault_salt")
        if salt_hex is None:
            salt = crypto_vault.new_salt()
            self._meta_set("vault_salt", salt.hex())
        else:
            salt = bytes.fromhex(salt_hex)
        try:
            cipher = crypto_vault.Cipher(passphrase, salt)
        except Exception as e:  # noqa: BLE001
            return False, str(e)
        verifier = self._meta_get("vault_verifier")
        if verifier is None:
            self._meta_set("vault_verifier", cipher.encrypt("REDEYE-VAULT-OK"))
        elif not cipher.verify(verifier):
            return False, "wrong passphrase"
        self.cipher = cipher
        return True, "vault encryption enabled"

    def encryption_on(self) -> bool:
        return self.cipher is not None

    def _enc(self, s: str) -> str:
        return self.cipher.encrypt(s or "") if self.cipher else (s or "")

    def _dec(self, s: str) -> str:
        return self.cipher.decrypt(s or "") if self.cipher else (s or "")

    # -- inventory ----------------------------------------------------------
    def upsert_asset(self, host, in_scope=None) -> None:
        """Insert/update from a state.Host (called as nodes are discovered).
        Preserves manually-entered notes, the original first_seen, and any
        manual in/out-of-scope toggle (in_scope is only set on first insert)."""
        now = time.time()
        ports = getattr(host, "ports", []) or []
        open_count = host.meta.get("open_count") if getattr(host, "meta", None) else None
        if open_count is None:
            open_count = sum(1 for p in ports if p.get("state") == "open")
        row = self.conn.execute("SELECT first_seen FROM inventory WHERE id=?",
                                 (host.id,)).fetchone()
        first_seen = row["first_seen"] if row else now
        insc = 1 if in_scope is None else (1 if in_scope else 0)
        self.conn.execute("""
            INSERT INTO inventory
              (id,label,kind,source,ip,hostname,os,status,open_count,
               ports_json,meta_json,notes,in_scope,first_seen,last_seen)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,COALESCE(
                       (SELECT notes FROM inventory WHERE id=?),''),?,?,?)
            ON CONFLICT(id) DO UPDATE SET
              label=excluded.label, kind=excluded.kind, source=excluded.source,
              ip=excluded.ip, hostname=excluded.hostname, os=excluded.os,
              status=excluded.status, open_count=excluded.open_count,
              ports_json=excluded.ports_json, meta_json=excluded.meta_json,
              last_seen=excluded.last_seen
        """, (host.id, host.label, getattr(host, "kind", "host"),
              getattr(host, "source", ""), getattr(host, "ip", ""),
              getattr(host, "hostname", ""), getattr(host, "os", ""),
              getattr(host, "status", ""), int(open_count),
              json.dumps(ports), json.dumps(getattr(host, "meta", {}) or {}),
              host.id, insc, first_seen, now))
        self.conn.commit()

    def set_asset_scope(self, asset_id: str, in_scope: bool) -> None:
        self.conn.execute("UPDATE inventory SET in_scope=? WHERE id=?",
                          (1 if in_scope else 0, asset_id))
        self.conn.commit()

    def recompute_scope(self, scope) -> None:
        """Re-flag every asset's in_scope from the current Scope (called when
        the scope changes). Manual toggles are overwritten by the new scope."""
        rows = self.conn.execute(
            "SELECT id, ip, hostname FROM inventory").fetchall()
        for r in rows:
            val = 1 if scope.matches_asset(r["ip"], r["hostname"]) else 0
            self.conn.execute("UPDATE inventory SET in_scope=? WHERE id=?",
                              (val, r["id"]))
        self.conn.commit()

    # -- correlation links (manual merge / dismissed suggestions) -----------
    def add_correlation_link(self, kind: str, a_id: str, b_id: str) -> None:
        self.conn.execute(
            "INSERT INTO correlation_links(kind,a_id,b_id,created) VALUES(?,?,?,?)",
            (kind, a_id, b_id, time.time()))
        self.conn.commit()

    def list_correlation_links(self) -> list:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM correlation_links").fetchall()]

    def delete_correlation_link(self, kind: str, a_id: str, b_id: str) -> None:
        self.conn.execute(
            "DELETE FROM correlation_links WHERE kind=? AND "
            "((a_id=? AND b_id=?) OR (a_id=? AND b_id=?))",
            (kind, a_id, b_id, b_id, a_id))
        self.conn.commit()

    # -- labels (named sets of host+port endpoints for batch ops) -----------
    def add_label_member(self, label: str, asset_id: str, port=-1) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO label_members(label,asset_id,port,created) "
            "VALUES(?,?,?,?)", (label, asset_id, int(port), time.time()))
        self.conn.commit()

    def remove_label_member(self, label: str, asset_id: str, port=-1) -> None:
        self.conn.execute(
            "DELETE FROM label_members WHERE label=? AND asset_id=? AND port=?",
            (label, asset_id, int(port)))
        self.conn.commit()

    def remove_label(self, label: str) -> None:
        self.conn.execute("DELETE FROM label_members WHERE label=?", (label,))
        self.conn.commit()

    def label_members(self, label: str) -> list:
        return [dict(r) for r in self.conn.execute(
            "SELECT asset_id, port FROM label_members WHERE label=?",
            (label,)).fetchall()]

    def list_labels(self) -> list:
        return [dict(r) for r in self.conn.execute(
            "SELECT label, COUNT(*) AS count FROM label_members "
            "GROUP BY label ORDER BY label").fetchall()]

    # -- snapshots (scan diffing) -------------------------------------------
    # -- tool integration instances ----------------------------------------
    def add_integration(self, iid: str, tool: str, name: str) -> str:
        self.conn.execute(
            "INSERT OR IGNORE INTO integrations(id,tool,name,config,created) "
            "VALUES(?,?,?,?,?)", (iid, tool, name, "{}", time.time()))
        self.conn.commit()
        return iid

    def list_integrations(self) -> list:
        out = []
        for r in self.conn.execute(
                "SELECT id,tool,name,config FROM integrations ORDER BY tool,name").fetchall():
            try:
                cfg = json.loads(r["config"] or "{}")
            except Exception:  # noqa: BLE001
                cfg = {}
            out.append({"id": r["id"], "tool": r["tool"], "name": r["name"],
                        "config": cfg})
        return out

    def get_integration(self, iid: str) -> dict | None:
        r = self.conn.execute(
            "SELECT id,tool,name,config FROM integrations WHERE id=?",
            (iid,)).fetchone()
        if not r:
            return None
        try:
            cfg = json.loads(r["config"] or "{}")
        except Exception:  # noqa: BLE001
            cfg = {}
        return {"id": r["id"], "tool": r["tool"], "name": r["name"], "config": cfg}

    def set_integration_field(self, iid: str, field: str, value: str) -> None:
        cur = self.get_integration(iid)
        if not cur:
            return
        cfg = cur["config"]
        if value == "":
            cfg.pop(field, None)
        else:
            cfg[field] = value
        self.conn.execute("UPDATE integrations SET config=? WHERE id=?",
                          (json.dumps(cfg), iid))
        self.conn.commit()

    def rename_integration(self, iid: str, name: str) -> None:
        self.conn.execute("UPDATE integrations SET name=? WHERE id=?", (name, iid))
        self.conn.commit()

    def remove_integration(self, iid: str) -> None:
        self.conn.execute("DELETE FROM integrations WHERE id=?", (iid,))
        self.conn.commit()

    def add_snapshot(self, label: str, data: dict) -> int:
        cur = self.conn.execute(
            "INSERT INTO snapshots(ts,label,data) VALUES(?,?,?)",
            (time.time(), label, json.dumps(data)))
        self.conn.commit()
        return cur.lastrowid

    def list_snapshots(self) -> list:
        return [{"id": r["id"], "ts": r["ts"], "label": r["label"]}
                for r in self.conn.execute(
                    "SELECT id, ts, label FROM snapshots ORDER BY id DESC").fetchall()]

    def get_snapshot(self, sid: int) -> dict | None:
        r = self.conn.execute("SELECT data FROM snapshots WHERE id=?",
                              (int(sid),)).fetchone()
        return json.loads(r["data"]) if r else None

    def delete_snapshot(self, sid: int) -> None:
        self.conn.execute("DELETE FROM snapshots WHERE id=?", (int(sid),))
        self.conn.commit()

    # -- screenshots (gowitness) --------------------------------------------
    def upsert_screenshot(self, url: str, image_b64: str, asset: str = "",
                          title: str = "", status: int = 0,
                          phash: str = "") -> None:
        self.conn.execute("""
            INSERT INTO screenshots(url,asset,title,image,status,phash,created)
            VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(url) DO UPDATE SET image=excluded.image,
                title=excluded.title, asset=excluded.asset,
                status=excluded.status, phash=excluded.phash,
                created=excluded.created
        """, (url, asset, title, image_b64, int(status or 0), phash, time.time()))
        self.conn.commit()

    def list_screenshots(self, with_image: bool = False) -> list:
        cols = "id,url,asset,title,status,phash,created" + (",image" if with_image else "")
        return [dict(r) for r in self.conn.execute(
            f"SELECT {cols} FROM screenshots ORDER BY id").fetchall()]

    def list_assets(self, order="last_seen DESC") -> list[sqlite3.Row]:
        return self.conn.execute(
            f"SELECT * FROM inventory ORDER BY {order}").fetchall()

    def count_assets(self) -> int:
        return self.conn.execute("SELECT COUNT(*) n FROM inventory").fetchone()["n"]

    def set_asset_notes(self, asset_id: str, notes: str) -> None:
        self.conn.execute("UPDATE inventory SET notes=? WHERE id=?",
                          (notes, asset_id))
        self.conn.commit()

    def delete_asset(self, asset_id: str) -> None:
        self.conn.execute("DELETE FROM inventory WHERE id=?", (asset_id,))
        self.conn.commit()

    # -- findings -----------------------------------------------------------
    def list_findings(self) -> list[sqlite3.Row]:
        order = ("CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 "
                 "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, updated DESC")
        return self.conn.execute(
            f"SELECT * FROM findings ORDER BY {order}").fetchall()

    def get_finding(self, fid: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM findings WHERE id=?",
                                 (fid,)).fetchone()

    def count_findings(self) -> int:
        return self.conn.execute("SELECT COUNT(*) n FROM findings").fetchone()["n"]

    def add_finding(self, title="Untitled finding", severity="MEDIUM",
                    status="open", hosts="", description="",
                    recommendation="", source="manual", dedupe=None) -> int:
        now = time.time()
        cur = self.conn.execute("""
            INSERT INTO findings
              (title,severity,status,hosts,description,recommendation,
               source,dedupe,created,updated)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (title, severity, status, hosts, description, recommendation,
             source, dedupe, now, now))
        self.conn.commit()
        return cur.lastrowid

    def upsert_scan_finding(self, dedupe: str, **fields) -> int:
        """Add or refresh a finding discovered by a scanner. Deduped on `dedupe`
        so re-scans update the same row instead of piling up duplicates. Never
        overwrites a status an operator has changed away from 'open'."""
        row = self.conn.execute("SELECT id,status FROM findings WHERE dedupe=?",
                                 (dedupe,)).fetchone()
        if row:
            upd = {k: v for k, v in fields.items()
                   if k in ("title", "severity", "hosts", "description",
                            "recommendation")}
            if upd:
                self.update_finding(row["id"], **upd)
            return row["id"]
        return self.add_finding(source=fields.get("source", "scan"),
                                dedupe=dedupe,
                                **{k: v for k, v in fields.items()
                                   if k in ("title", "severity", "status",
                                            "hosts", "description",
                                            "recommendation")})

    def update_finding(self, fid: int, **fields) -> None:
        allowed = {"title", "severity", "status", "hosts", "description",
                   "recommendation", "cvss", "cwe", "evidence"}
        sets = {k: v for k, v in fields.items() if k in allowed}
        if not sets:
            return
        sets["updated"] = time.time()
        cols = ", ".join(f"{k}=?" for k in sets)
        self.conn.execute(f"UPDATE findings SET {cols} WHERE id=?",
                          (*sets.values(), fid))
        self.conn.commit()

    def delete_finding(self, fid: int) -> None:
        self.conn.execute("DELETE FROM findings WHERE id=?", (fid,))
        self.conn.commit()

    def set_finding_ticket(self, fid: int, ticket: str) -> None:
        self.conn.execute("UPDATE findings SET ticket=?, updated=? WHERE id=?",
                          (ticket, time.time(), fid))
        self.conn.commit()

    # -- activity log -------------------------------------------------------
    def log_activity(self, kind: str, text: str, detail: str = "") -> int:
        cur = self.conn.execute(
            "INSERT INTO activity(ts,kind,text,detail) VALUES(?,?,?,?)",
            (time.time(), kind, text, detail))
        self.conn.commit()
        return cur.lastrowid

    def list_activity(self, limit: int = 1000, kind: str | None = None):
        if kind:
            return self.conn.execute(
                "SELECT * FROM activity WHERE kind=? ORDER BY id DESC LIMIT ?",
                (kind, limit)).fetchall()
        return self.conn.execute(
            "SELECT * FROM activity ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def count_activity(self) -> int:
        return self.conn.execute("SELECT COUNT(*) n FROM activity").fetchone()["n"]

    def clear_activity(self) -> None:
        self.conn.execute("DELETE FROM activity")
        self.conn.commit()

    def export_activity_csv(self, path: str | None = None) -> tuple[str, int]:
        rows = self.conn.execute(
            "SELECT * FROM activity ORDER BY id ASC").fetchall()
        if path is None:
            ts = time.strftime("%Y%m%d-%H%M%S")
            path = _unique(os.path.join(self._export_dir(), f"activity_{ts}.csv"))
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["time", "kind", "text", "detail"])
            for r in rows:
                w.writerow([_iso(r["ts"]), r["kind"], r["text"], r["detail"]])
        return path, len(rows)

    # -- vault --------------------------------------------------------------
    def add_credential(self, kind="credential", label="", username="",
                       secret="", scope="", source="manual",
                       status="untested", notes="", dedupe=None) -> int:
        now = time.time()
        cur = self.conn.execute("""
            INSERT INTO vault
              (kind,label,username,secret,scope,source,status,notes,dedupe,
               created,updated)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (kind, label, username, self._enc(secret), scope, source, status,
             notes, dedupe, now, now))
        self.conn.commit()
        return cur.lastrowid

    def upsert_discovered_secret(self, kind="secret", label="", username="",
                                 secret="", scope="", source="scan",
                                 notes="") -> int:
        """Ingest a credential/secret found by a scan, deduped on its content so
        the same leak across re-scans doesn't create duplicate rows."""
        key = hashlib.sha1(
            f"{kind}|{username}|{secret}|{scope}".encode("utf-8")).hexdigest()
        row = self.conn.execute("SELECT id FROM vault WHERE dedupe=?",
                                 (key,)).fetchone()
        now = time.time()
        if row:
            self.conn.execute(
                "UPDATE vault SET label=?, source=?, notes=?, updated=? WHERE id=?",
                (label or "", source, notes, now, row["id"]))
            self.conn.commit()
            return row["id"]
        return self.add_credential(kind=kind, label=label, username=username,
                                   secret=secret, scope=scope, source=source,
                                   status="untested", notes=notes, dedupe=key)

    def list_vault(self, kind: str | None = None):
        if kind:
            return self.conn.execute(
                "SELECT * FROM vault WHERE kind=? ORDER BY updated DESC",
                (kind,)).fetchall()
        return self.conn.execute("SELECT * FROM vault ORDER BY updated DESC").fetchall()

    def get_credential(self, cid: int):
        return self.conn.execute("SELECT * FROM vault WHERE id=?", (cid,)).fetchone()

    def reveal_secret(self, cid: int) -> str:
        r = self.get_credential(cid)
        return self._dec(r["secret"]) if r else ""

    def count_vault(self) -> int:
        return self.conn.execute("SELECT COUNT(*) n FROM vault").fetchone()["n"]

    def update_credential(self, cid: int, **fields) -> None:
        allowed = {"kind", "label", "username", "scope", "status", "notes"}
        sets = {k: v for k, v in fields.items() if k in allowed}
        if "secret" in fields:
            sets["secret"] = self._enc(fields["secret"])
        if not sets:
            return
        sets["updated"] = time.time()
        cols = ", ".join(f"{k}=?" for k in sets)
        self.conn.execute(f"UPDATE vault SET {cols} WHERE id=?",
                          (*sets.values(), cid))
        self.conn.commit()

    def set_cred_status(self, cid: int, status: str) -> None:
        self.conn.execute(
            "UPDATE vault SET status=?, last_tried=?, updated=? WHERE id=?",
            (status, time.time(), time.time(), cid))
        self.conn.commit()

    def delete_credential(self, cid: int) -> None:
        self.conn.execute("DELETE FROM vault WHERE id=?", (cid,))
        self.conn.commit()

    # -- CSV export ---------------------------------------------------------
    def _export_dir(self) -> str:
        d = os.path.join(os.path.dirname(os.path.abspath(self.path)), "exports")
        os.makedirs(d, exist_ok=True)
        return d

    def asset_label_map(self) -> dict:
        out = {}
        for r in self.conn.execute(
                "SELECT DISTINCT label, asset_id FROM label_members").fetchall():
            out.setdefault(r["asset_id"], []).append(r["label"])
        return out

    def export_inventory_csv(self, path: str | None = None) -> tuple[str, int]:
        rows = self.list_assets(order="ip")
        labelmap = self.asset_label_map()
        if path is None:
            ts = time.strftime("%Y%m%d-%H%M%S")
            path = _unique(os.path.join(self._export_dir(), f"inventory_{ts}.csv"))
        cols = ["id", "label", "kind", "source", "ip", "hostname", "os",
                "status", "open_count", "ports", "in_scope", "labels", "notes",
                "first_seen", "last_seen"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(cols)
            for r in rows:
                ports = ", ".join(
                    f"{p.get('port')}/{p.get('proto','tcp')}"
                    f"({p.get('service','')})".strip()
                    for p in json.loads(r["ports_json"] or "[]")
                    if p.get("state") == "open")
                insc = "yes" if ("in_scope" not in r.keys() or r["in_scope"]) else "no"
                labels = ", ".join(labelmap.get(r["id"], []))
                w.writerow([r["id"], r["label"], r["kind"], r["source"],
                            r["ip"], r["hostname"], r["os"], r["status"],
                            r["open_count"], ports, insc, labels, r["notes"],
                            _iso(r["first_seen"]), _iso(r["last_seen"])])
        return path, len(rows)

    def export_findings_csv(self, path: str | None = None) -> tuple[str, int]:
        rows = self.list_findings()
        if path is None:
            ts = time.strftime("%Y%m%d-%H%M%S")
            path = _unique(os.path.join(self._export_dir(), f"findings_{ts}.csv"))
        cols = ["id", "severity", "status", "source", "title", "hosts",
                "description", "recommendation", "created", "updated"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(cols)
            for r in rows:
                src = r["source"] if "source" in r.keys() else "manual"
                w.writerow([r["id"], r["severity"], r["status"], src, r["title"],
                            r["hosts"], r["description"], r["recommendation"],
                            _iso(r["created"]), _iso(r["updated"])])
        return path, len(rows)

    def export_vault_csv(self, path: str | None = None,
                         reveal: bool = True) -> tuple[str, int]:
        """Export the vault. reveal=True writes decrypted secrets (this file
        then contains live credentials -- handle accordingly); reveal=False
        redacts the secret column."""
        rows = self.list_vault()
        if path is None:
            ts = time.strftime("%Y%m%d-%H%M%S")
            path = _unique(os.path.join(self._export_dir(), f"vault_{ts}.csv"))
        cols = ["id", "kind", "label", "username", "secret", "scope", "source",
                "status", "notes", "created", "updated", "last_tried"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(cols)
            for r in rows:
                sec = self._dec(r["secret"]) if reveal else "<redacted>"
                w.writerow([r["id"], r["kind"], r["label"], r["username"], sec,
                            r["scope"], r["source"], r["status"], r["notes"],
                            _iso(r["created"]), _iso(r["updated"]),
                            _iso(r["last_tried"])])
        return path, len(rows)

    def export_report_md(self, path: str | None = None) -> tuple[str, int]:
        """Write a Markdown engagement report pulling together findings,
        inventory, the vault (no secret values), and recent activity."""
        findings = self.list_findings()
        assets = self.list_assets(order="ip")
        vault = self.list_vault()
        activity = self.list_activity(limit=40)
        if path is None:
            ts = time.strftime("%Y%m%d-%H%M%S")
            path = _unique(os.path.join(self._export_dir(), f"report_{ts}.md"))

        sev_counts = {s: 0 for s in SEVERITIES}
        for r in findings:
            sev_counts[r["severity"]] = sev_counts.get(r["severity"], 0) + 1
        open_hosts = [a for a in assets if a["open_count"]]

        L = []
        L.append("# REDEYE engagement report\n")
        L.append(f"_Generated {time.strftime('%Y-%m-%d %H:%M:%S')}_\n")
        L.append("## Summary\n")
        L.append(f"- Findings: {len(findings)}  "
                 + " · ".join(f"{s} {sev_counts[s]}" for s in SEVERITIES) + "\n")
        L.append(f"- Assets: {len(assets)} ({len(open_hosts)} with open ports)\n")
        L.append(f"- Vault entries: {len(vault)}\n")

        L.append("\n## Findings\n")
        if findings:
            L.append("| # | Severity | Status | Title | Affected | Ticket |")
            L.append("|---|---|---|---|---|---|")
            for r in findings:
                tk = r["ticket"] if "ticket" in r.keys() and r["ticket"] else ""
                L.append(f"| {r['id']} | {r['severity']} | {r['status']} | "
                         f"{_md(r['title'])} | {_md(r['hosts'])} | {_md(tk)} |")
            for r in findings:
                if r["description"] or r["recommendation"]:
                    L.append(f"\n### #{r['id']} {_md(r['title'])} "
                             f"({r['severity']}/{r['status']})")
                    if r["hosts"]:
                        L.append(f"*Affected:* {_md(r['hosts'])}")
                    if r["description"]:
                        L.append(f"\n{r['description']}")
                    if r["recommendation"]:
                        L.append(f"\n**Recommendation:** {r['recommendation']}")
        else:
            L.append("_No findings recorded._")

        L.append("\n## Inventory (hosts with open ports)\n")
        if open_hosts:
            L.append("| Asset | IP / host | Open | Services |")
            L.append("|---|---|---|---|")
            for a in open_hosts:
                svc = ", ".join(
                    f"{p.get('port')}/{p.get('service','')}".rstrip("/")
                    for p in json.loads(a["ports_json"] or "[]")
                    if p.get("state") == "open")
                L.append(f"| {_md(a['label'])} | {_md(a['ip'] or a['hostname'])} "
                         f"| {a['open_count']} | {_md(svc)} |")
        else:
            L.append("_No exposed services recorded._")

        L.append("\n## Vault (secrets redacted)\n")
        if vault:
            L.append("| Kind | Username | Scope | Status | Source |")
            L.append("|---|---|---|---|---|")
            for v in vault:
                L.append(f"| {v['kind']} | {_md(v['username'] or '-')} | "
                         f"{_md(v['scope'] or '-')} | {v['status']} | "
                         f"{_md(v['source'])} |")
        else:
            L.append("_Vault empty._")

        L.append("\n## Recent activity\n")
        if activity:
            for r in reversed(activity):
                L.append(f"- `{_iso(r['ts'])}` **{r['kind']}** {_md(r['text'])}")
        else:
            L.append("_No activity logged._")

        L.append("\n---\n_Only for systems you are authorised to test._\n")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(L))
        return path, len(findings)

    def close(self):
        try:
            self.conn.close()
        except Exception:  # noqa: BLE001
            pass


def _unique(path: str) -> str:
    """Avoid clobbering an existing export written in the same second."""
    if not os.path.exists(path):
        return path
    stem, ext = os.path.splitext(path)
    i = 2
    while os.path.exists(f"{stem}-{i}{ext}"):
        i += 1
    return f"{stem}-{i}{ext}"


def _md(s) -> str:
    """Escape a cell for a Markdown table (pipes/newlines)."""
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ").strip()


def _iso(ts) -> str:
    if not ts:
        return ""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
