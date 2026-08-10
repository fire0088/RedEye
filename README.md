# REDEYE

A red-team console with a watchful red eye, RED. Talk to an LLM on **AWS Bedrock**, let it drive
**modular MCP recon servers** (nmap + a Roslyn .NET endpoint-discovery server
ship in the box), and **fly through discovered hosts on a 3D network map**.

> ### ⚑ Godot front-end + Python daemon
> **REDEYE runs on Godot now — pygame has been removed.** The engine is split in
> two: a **headless Python backend daemon** (all the Bedrock / MCP / SQLite /
> vault logic — unchanged and tested) and a **Godot 4 front-end** that talks to
> it over a local socket.
>
> ```
> pip install -r requirements.txt
> python main.py             # 1. start the backend (alias of: python serve.py)
> # 2. open godot/ in Godot 4.2+ and press F5
> ```
>
> **Multiplayer:** the daemon accepts many clients at once (each on its own
> thread) and everyone shares one session. Sign in with any username + the access
> password printed on startup (also written to `config.cfg` `[server]password`).
> Use `--host 0.0.0.0` for LAN play.
>
> There is no pygame dependency and no `main.py` pygame UI anymore — `main.py`
> just launches the daemon. See **`godot/README.md`** for the full run
> instructions, the wire protocol, and the per-view migration checklist. Note the
> Godot GDScript is written but not yet run against a real Godot runtime, so
> expect to fix small API details on first launch; the Python backend is tested.
> The interaction model described in the sections below (views, findings/vault
> actions, the map) now lives in the Godot client.

```
  boot / select core   ->   RED console (chat + tools)   <->   network map (WASD)
```

- Glowing red eye (RED) that reacts to state (idle / thinking / speaking / alert)
- CRT scanlines, vignette, red-team palette
- Bedrock **Converse** with streaming + tool-use (works across model families)
- MCP tool fabric — **add a server by editing one JSON file, no code changes**
- 3D flythrough map with **drag-to-look**; right-click a node for a context menu (view ports, rescan, attempt auth, log finding, interrogate via RED)
- **Map filter & scope** — filter nodes by port / OS / service / auth (`port:443 os:linux svc:nginx`); the matched set becomes the engagement scope, and you can run a query, rescan, auth attempt, or finding against **all** scoped targets at once
- **Inventory database** — every discovered host/endpoint is persisted (SQLite), browsable as a table, annotatable with notes, exportable to CSV
- **Findings database** — a manual editor for security findings (title / severity / hosts / status / description / recommendation), exportable to CSV. Scanners (nuclei, wapiti) write findings here automatically, deduped. **Right-click a finding** to retest it, export a runnable Python PoC, file a Jira ticket, hand it to RED, or mark it remediated.
- **Activity log** (`F6`) — a persistent, cross-session audit trail of commands run and significant discoveries (hosts, findings, captured secrets, errors), filterable and exportable to CSV
- **Key vault** — store credentials/secrets for authentication attempts, added by hand or captured automatically from scans; masked by default, optionally **encrypted at rest** (PBKDF2 + Fernet), exportable to CSV
- **Shipped scanner integrations** — nmap, .NET endpoint discovery (reachnet/Roslyn), **nuclei**, and **wapiti**, each with a real-binary passthrough and a mock mode; adding another is one JSON block + one extractor function
- **Cloud / EDR / vuln-management integrations** — **AWS** (via a named `.aws` profile: EC2 servers, Lambdas, ECS containers, ELB network devices + Amazon Inspector2 vulns), **CrowdStrike Falcon** (hosts + Spotlight vulns), **Tenable.io** (assets + vulns), and **Wiz** (cloud resources + vuln findings, via API). They build out the inventory/map (nodes coloured by kind: server / container / lambda / network device / database) and write CVE findings to the findings DB. Ask RED things like *"find remote vulns in 10.0.0.0/24"* and the `subnet` filter scopes the query. Each server uses the real API when credentials are present and clearly-flagged **mock** data otherwise, so it works out of the box
- **config.cfg** — keep window size, CRT, audio, AWS defaults, paths, and vault settings in a file instead of on the command line
- **Procedural sci-fi audio** — every UI sound (hover, click, menu, discovery ping, RED transmit, alerts, power-on) is synthesised at runtime; no asset files, mutable with `Ctrl+M`, volume via `Ctrl+ -`/`Ctrl+ +`
- **Help overlay** (`Ctrl+H`) and transient toast notifications

---

## 1. Install

```bash
pip install -r requirements.txt        # pygame, mcp>=2.0, boto3
```

Optional but recommended for real scans:

```bash
sudo apt-get install nmap              # otherwise nmap runs in MOCK mode
```

## 2. AWS / Bedrock

REDEYE uses your standard AWS profile chain. Make sure you have:

- a profile in `~/.aws/credentials` / `~/.aws/config`, and
- **model access granted** in the Bedrock console (Model access page) for the
  models you want, in the region you pick.

The boot screen lists your profiles, a region, then queries Bedrock for the
models actually available to you (foundation models **and** inference profiles —
many current models are only reachable via a profile id).

## 3. Run

```bash
python main.py                         # reads config.cfg next to main.py
# flags override config.cfg:
python main.py --no-crt                # disable the CRT overlay
python main.py --no-sound              # start muted (toggle later with Ctrl+M)
python main.py --size 1600x900
python main.py --config myrun.cfg      # a different settings file
python main.py --mcp other_servers.json
```

**Settings live in `config.cfg`** (an INI file) so you don't have to remember
flags. It has `[display]` (size, crt, fullscreen), `[audio]` (enabled, volume),
`[aws]` (profile, region, model — blank means choose on the boot screen),
`[paths]` (mcp_config, db, exports), and `[vault]` (encrypt, passphrase). Any
flag you pass on the command line wins over the file; a missing file just falls
back to built-in defaults.

Boot flow: **profile → region → inference core → connect**. Then you land in the
RED console. Try:

```
scan localhost
sweep 10.0.0.0/24 then port-scan anything with web ports
discover the .NET endpoints in /src/MyApi and flag the anonymous ones
```

RED calls the MCP tools itself; every host/endpoint it finds is plotted on the
map. Press **TAB** to fly through it.

---

## 4. Controls

**Anywhere** (after connect): `F1` console · `F2` map · `F3` inventory · `F4` findings · `F5` vault · `F6` log.
`Ctrl+H` help · `Ctrl+M` mute · `Ctrl+ -`/`Ctrl+ +` volume · `Ctrl+R` write report · `F11` fullscreen · `Ctrl+Q` quit.

**Console**

| key | action |
|-----|--------|
| type + Enter | send a directive to RED |
| scroll | chat history |
| TAB | network map |

**Network map**

| key | action |
|-----|--------|
| W / S | forward / back |
| A / D | strafe |
| R / F (or Space / Ctrl) | up / down |
| **drag mouse** | **look around** |
| arrow keys | look |
| Shift | boost |
| mouse wheel | zoom (FOV) |
| G / Home | frame all nodes |
| `/` | filter & scope the map |
| left-click | select node (details panel) |
| **right-click node** | node **context menu** |
| **right-click empty** | **scope actions** (when a filter is active) |
| TAB | back to console |

Press `/` to filter the map with a small query language — clauses are ANDed,
`-` negates one: `port:443`, `port:80,443,8000-8100`, `os:linux`, `svc:nginx`,
`status:up`, `kind:endpoint`, `auth:anonymous`, `open`, `-port:22`, or a bare
word to match ip/host/service. Out-of-scope nodes ghost out; the matched set is
your **scope** (shown in the HUD). Right-click empty space for scope actions that
hit every target at once: **query via RED** (type a command, it's run per target),
**rescan (nmap)**, **attempt auth (vault)**, or **log a finding**. `Esc` clears the
filter.

**Inventory** (`F3`)

| key | action |
|-----|--------|
| up / down / wheel | select an asset |
| `E` | export inventory to CSV |
| `F` | create a finding pre-filled from the selected asset |
| `Del` (twice) | delete the asset |
| `TAB` | back to console |

**Findings** (`F4`)

| key | action |
|-----|--------|
| `Tab` / `Shift+Tab` | move between editor fields |
| click a field | focus it |
| `Left` / `Right` | change severity or status (when that field is focused) |
| `Up` / `Down` | move the caret (description / recommendation) |
| `Ctrl+N` | new finding |
| `Ctrl+S` | save |
| `Ctrl+D` (twice) | delete finding |
| `Ctrl+E` | export findings to CSV |
| `PageUp` / `PageDown` | move through the findings list |

---

## 5. Inventory & findings databases

Both databases live in a single SQLite file (`redeye.db`, created next to
`mcp_config.json`; override with `"db_path"` in the config). No server, no extra
dependencies — it's stdlib `sqlite3`, so the data is yours and portable.

**Inventory** auto-populates. Every host and endpoint RED discovers is written to
the `inventory` table (id, label, kind, ip/hostname, os, open-port count, full
port list, source, first/last seen). Re-scans update rows in place and preserve
any notes. Browse it on the Inventory screen; `E` writes a timestamped CSV to an
`exports/` folder and logs the path to the console.

**Findings** is manual — that's the point. The Findings screen is a two-pane
editor: the list of findings on the left (severity-sorted, colour-coded), and on
the right the fields you asked for — **title, severity, hosts/locations, status,
description, and recommendation.** Tab through the fields, arrow through severity
(`CRITICAL/HIGH/MEDIUM/LOW/INFO`) and status (`open/triage/confirmed/remediated/
closed`), and `Ctrl+S` to persist. `Ctrl+E` exports all findings to CSV.

You rarely start a finding from scratch: on the **map**, right-click any host or
endpoint → **log finding**, or on the **Inventory** screen press `F`. Either one
opens the editor pre-filled (title, hosts, a first-draft description and
recommendation, and a severity guess) so you just refine and save.

CSV columns — inventory: `id,label,kind,source,ip,hostname,os,status,open_count,
ports,notes,first_seen,last_seen`; findings: `id,severity,status,title,hosts,
description,recommendation,created,updated`.

---

## 6. Key vault & authentication attempts

The **vault** (`F5`) is where credentials and secrets live for auth attempts.
Entries arrive two ways:

- **By hand** — press `A`, fill in kind / label / username / secret / scope /
  notes, `Ctrl+S` to save. `E` edits, `S` reveals a masked secret, `V`/`I`/`U`
  mark a credential valid / invalid / untested, `Del` (twice) removes it.
- **From scans** — any server whose extractor yields a `VaultUpsert` feeds the
  vault automatically (the shipped nuclei server does this when a template
  extracts a secret, e.g. an exposed `.env`). Scan-sourced rows are tagged
  `scan:<server>` and deduped on their content.

**Trying authentication.** Press `T` on a vault entry, or right-click a host on
the map → **attempt auth (vault)**. REDEYE hands RED the target plus the matching
credentials *by reference* (id / username / kind — never the secret text) and asks
it to run an auth/login tool if one is wired in, or otherwise outline the
approach. Wire in a real auth tool the same way as any other MCP server.

**Encryption at rest.** Secrets are masked in the UI and can be encrypted on
disk. In `config.cfg`:

```ini
[vault]
encrypt    = true
passphrase =            # prefer the env var below over writing it here
```

The passphrase is read from `REDEYE_VAULT_PASSPHRASE` first, then the file.
Encryption uses PBKDF2-HMAC-SHA256 (200k iterations) to derive a Fernet key from
your passphrase and a per-database salt; a stored verifier detects a wrong
passphrase instead of silently returning garbage. Without a passphrase (or
without the `cryptography` package) the vault stays plaintext and says so in the
header. CSV export (`X`) writes secrets **in the clear** and warns you — treat
that file like the credentials it contains.

---

## 7. Finding actions & the activity log

**Right-click any finding** (F4) for a context menu:

- **retest** — re-runs the scan that produced it. If the source scanner is
  connected it fires the tool directly against the finding's target; otherwise it
  hands a retest directive to RED. Either way you land in the console to watch.
- **export PoC (.py)** — writes a standalone, runnable Python script to `exports/`:
  a `requests` skeleton for URL findings, a `socket` skeleton for host:port
  findings, pre-filled with the finding's metadata and a `# TODO` where you drop
  the retest assertion. Run it, edit it, keep it with the engagement.
- **create jira ticket** — if `[jira]` is set in `config.cfg` (base_url + email +
  token; token preferably via `REDEYE_JIRA_TOKEN`) it POSTs a real issue and
  stores the key on the finding; otherwise it writes an importable JSON payload to
  `exports/`. Findings with a ticket show a `◈` marker; **view jira ticket**
  then appears in the menu.
- **ask RED about this** / **mark remediated** / **delete** round out the menu.

The **activity log** (`F6`) is a persistent audit trail written to SQLite as you
work: every tool RED runs, every operator directive, new hosts, scanner findings,
captured secrets, connects, errors, and exports. Filter by kind with `F`, export
to CSV with `E`, clear with `C` (twice). Because it's on disk it spans sessions,
so you can reconstruct exactly what was done and when.

**Engagement report.** `Ctrl+R` (anywhere) writes a Markdown report to `exports/`
that pulls the whole picture together: a severity summary, the full findings
table plus per-finding detail, hosts with open ports and their services, a vault
summary (**secrets redacted**), and the recent activity trail. It's a one-key
hand-off artifact for whoever writes up the engagement.

---

## 8. Adding an MCP server (the modular part)

Everything is driven by **`mcp_config.json`**. To add a capability, add a block:

```json
"my-tool": {
  "name": "my tool",
  "category": "recon",
  "transport": "stdio",
  "command": "python3",
  "args": ["servers/my_tool_server.py"],
  "env": { "SOME_KEY": "value" },
  "color": [120, 255, 120],
  "extractor": "",
  "enabled": true
}
```

- `command` + `args` launch any MCP stdio server (Python, Node, a binary, `npx …`).
- `color` is how the server + its nodes appear on the map.
- `extractor` routes tool results into the app. Built in: `"nmap"`, `"roslyn"`,
  `"nuclei"`, `"wapiti"`, `"secret"`, or `""` (chat only). An extractor can
  yield any mix of three event types:

```python
from .bridge import HostUpsert, FindingUpsert, VaultUpsert

@register("mytool")
def _mytool(tool_name, data):
    for item in data.get("things", []):
        yield HostUpsert(id=f"mytool:{item['id']}", label=item["name"],
                         source="", kind="host", color=(120, 255, 120))  # map node
    for v in data.get("vulns", []):
        yield FindingUpsert(dedupe=f"mytool:{v['id']}", title=v["name"],
                            severity="HIGH", hosts=v["url"])              # findings DB
    for s in data.get("secrets", []):
        yield VaultUpsert(kind="credential", username=s["user"],
                          secret=s["pass"], scope=s["host"])             # key vault
```

`HostUpsert` → a node on the 3D map (and a row in the inventory DB).
`FindingUpsert` → a deduped row in the findings DB (that's how nuclei/wapiti
auto-populate findings). `VaultUpsert` → a deduped entry in the key vault (that's
how scans feed captured creds/secrets in). That's the whole extension surface:
**one config block + one extractor function.** Tool schemas are auto-translated
into Bedrock's tool format, so RED can call anything you wire in immediately.

**Shipped scanners** follow a convention worth copying: each exposes a
`scan(target, …)` tool, runs the real binary when it's on `PATH` and returns
clearly-flagged **mock** data otherwise (set `REDEYE_<TOOL>_MOCK=1` to force it),
and points at the binary via `REDEYE_<TOOL>_BIN`. Start from
**`servers/_template_server.py`** — a minimal, copy-me scanner that emits a host,
a finding, and a discovered credential so you can see all three event shapes at
once. So adding **nuclei**, **wapiti**, or your own tool is: copy the template,
wire the binary, add the config block, (optionally) write the extractor.

---

## 9. Wiring in your Roslyn .NET endpoint extractor

`servers/roslyn_endpoints_server.py` is a thin adapter over the Roslyn-based
endpoint extractor (routes + HTTP verb + auth classification + handler symbol,
incl. minimal-API entry points). Point it at your extractor with an env var in
the config's `env` block (or your shell):

```
REDEYE_ROSLYN_CMD = "dotnet /opt/reachnet/EndpointExtractor.dll --json {project}"
```

`{project}` is substituted with the project path. Your command must print JSON to
stdout in either shape:

```json
{"app":"OrdersApi","base_url":"https://…",
 "endpoints":[{"route":"/api/orders/{id}","verb":"GET",
               "auth":"authenticated","handler":"Ns.OrdersController::GetById/1"}]}
```

…or `{"apps": [ {…}, … ]}`. Without `REDEYE_ROSLYN_CMD` set, the server returns
clearly-flagged **mock** endpoints so the map is populated for demos. Endpoints
are coloured by auth posture — **anonymous endpoints are flagged red**.

Same story for nmap: set `REDEYE_NMAP_MOCK=1` to force mock data, or
`REDEYE_NMAP_BIN=/path/to/nmap` to point at a specific binary.

---

## 10. Architecture

```
config.cfg ─> settings.py ─┐
main.py ──> redeye/app.py  │      pygame loop + view manager (MAIN THREAD)
             │   views: view_boot / view_console / view_map / view_inventory
             │          view_findings / view_vault / view_log   (F1..F6)
             │   ui: red_eye, widgets (TextArea, ToastStack, HelpOverlay), theme
             │   audio.py (SFX)  exporters.py (PoC+Jira)  filters.py (scope DSL)
             │
             ├─ state.py          single-writer app state (chat, hosts, servers)
             ├─ database.py       SQLite: inventory + findings + vault + activity
             │     └─ crypto_vault.py   PBKDF2 + Fernet at-rest encryption
             │
             └─ bridge.py ──> worker.py   asyncio loop (WORKER THREAD)
                    ▲  │           ├─ bedrock.py     Converse: models + streaming
                    │  │           ├─ mcp_manager.py config-driven MCP connections
              events│  │commands   ├─ agent.py       LLM <-> tool loop (RED persona)
                    │  ▼           └─ extractors.py  results -> Host/Finding/Vault
              (thread-safe queues)

servers/nmap_server.py  roslyn_endpoints_server.py  ┐ shipped MCP stdio servers
servers/nuclei_server.py  wapiti_server.py          │ (real binary or mock)
servers/aws_server.py  crowdstrike_server.py        │ cloud / EDR / vuln-mgmt
servers/tenable_server.py  wiz_server.py            │ (real API or mock)
servers/_apiutil.py                                 │ shared HTTP + CIDR helpers
servers/_template_server.py                         ┘ copy-me scanner template
```

Discovery flows one way into the databases: worker → `HostUpsert` /
`FindingUpsert` / `VaultUpsert` event → main thread writes `state.hosts` and the
relevant table. The findings DB is also authored from the UI; the vault is
authored from the UI and fed by scans. All views read straight from SQLite, so
what you see is always what's on disk.

pygame stays on the main thread; all inference and tool I/O runs on one
background asyncio thread. They communicate only through two queues of plain
dataclasses, so there's no shared mutable state and no locks.

---

## 11. Safety / scope

This is authorised-engagement tooling. **Only scan and enumerate assets you have
explicit permission to test.** nmap traffic and endpoint probing are noisy and,
against systems you don't own, potentially illegal. The mock modes let you demo
and develop the UI without touching any real network.
