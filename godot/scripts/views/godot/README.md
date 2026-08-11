# REDEYE — Godot front-end

This is the Godot 4 front-end for REDEYE. It is a **thin client**: all the real
work (AWS Bedrock inference, MCP tool servers, the SQLite inventory / findings /
vault, crypto, exporters) runs in the Python **backend daemon**. Godot just
renders and relays.

```
   Godot front-end  ──JSON over TCP (127.0.0.1:8787)──►  Python backend daemon
   (this project)   ◄──events / rpc replies────────────  (serve.py)
                                                          │
                                          Bedrock · MCP servers · SQLite · vault
```

## Running it

1. **Start the backend daemon** (from the repo root, one directory up):

   ```
   pip install -r requirements.txt
   python serve.py                 # 127.0.0.1:8787
   python serve.py --host 0.0.0.0  # ...or let other machines on the LAN connect
   ```

   On startup it prints — and writes to `config.cfg` under `[server]password` —
   a freshly generated **access password**. Share it with whoever should connect.
   Pass `--keep-password` to stop it rotating each run.

2. **Open this `godot/` folder** as a project in Godot 4.4+ (4.7 recommended) and press **F5**.
   On the boot screen, **sign in** with any callsign (username) plus that access
   password, then pick an AWS profile + region, hit **LIST MODELS**, choose one,
   and **ESTABLISH LINK**. You land in the console.

**Multiplayer.** Multiple people can run the Godot client against the same
daemon at once. Everyone shares one session — one RED, one inventory / findings /
vault / map. Directives any operator types are echoed to all (tagged with their
callsign), worker output streams to everyone, and join/leave + the operator
roster show in the console. The nav bar (or **F1–F6**) switches views.

## Architecture

- `scripts/backend.gd` — autoload `Backend`. TCP client + JSON line framing.
  `Backend.send_command({...})` for fire-and-forget commands;
  `await Backend.call_rpc("name", {args})` for request/reply DB calls;
  connect to `Backend.event` for the worker event stream.
- `scripts/palette.gd` — autoload `Palette`. Colours mirrored from the old
  `theme.py` (RED, AMBER, severity/kind helpers).
- `Main.tscn` + `scripts/main.gd` — the shell: nav bar, view stack, CRT overlay,
  routes `Backend` signals to the active view. Views are plain `Control`
  subclasses instantiated in code, so `Main.tscn` is the only hand-authored
  scene.
- `scripts/eye.gd` + `shaders/red_eye.gdshader` — the RED eye.
- `shaders/crt.gdshader` — CRT scanlines / vignette / aberration overlay.
- `scripts/views/*.gd` — one file per view.

## Wire protocol (what the daemon speaks)

Client → daemon: `{"cmd":"auth","user":..,"password":..}` **first** (required),
then `{"cmd":"list_models|connect|user_message|call_tool|shutdown", ...}` and
`{"rpc":"<name>","rid":N, ...args}`.
Daemon → client: `{"type":"auth_required"}` on connect, `{"type":"hello",...}`
after auth (or `{"type":"auth_error",...}` and disconnect), `{"type":"Presence",
...}` / `{"type":"ChatEcho",...}` for the shared session, `{"type":"<EventName>",
...}` worker events, and `{"type":"rpc_result","rid":N,...}`. Full list in
`redeye/daemon.py`.

The daemon serves each client on its own thread; all Store access is serialised
behind one lock, and each socket has its own write lock so the broadcast pump and
that client's RPC replies don't interleave.

## Migration status (pygame view → Godot)

| Old pygame module        | Godot                     | Status |
|--------------------------|---------------------------|--------|
| `bridge`/`worker`/`agent`/`bedrock`/`mcp_manager`/`extractors`/`database`/`crypto_vault`/`exporters`/`settings`/`state`/`filters`/`cam3d` | reused unchanged behind `daemon.py` | **done, tested** |
| `app.py` (shell/nav/CRT) | `main.gd` + `crt.gdshader` | built, unrun |
| `red_eye.py`             | `eye.gd` + `red_eye.gdshader` | built, unrun |
| `theme.py`               | `palette.gd`              | built, unrun |
| `view_boot.py`           | `views/boot.gd`           | built, unrun |
| `view_console.py`        | `views/console.gd`        | built, unrun |
| `view_findings.py`       | `views/findings.gd`       | built, unrun |
| `view_inventory.py`      | `views/inventory.gd`      | built, unrun |
| `view_vault.py`          | `views/vault.gd`          | built, unrun |
| `view_log.py`            | `views/log.gd`            | built, unrun |
| `view_map.py` (3D + DSL) | `views/map.gd`            | **scaffold** — fly + nodes work; picking, labels, filter/scope DSL, per-node menu still TODO |
| `widgets.py` (ContextMenu/Toast/Help) | inline in views | partial — shared toast/help overlay TODO |
| `audio.py` (procedural SFX) | —                      | **TODO** — port to `AudioStreamGenerator` |

## Honest caveats

- **The GDScript has not been run.** It was written for Godot 4.2 but there is
  no Godot binary in the environment it was authored in, so expect to fix small
  API details (signal arg shapes, `Tree`/`PopupMenu` quirks) on first launch.
  The **backend daemon, by contrast, is tested** over a real socket.
- The socket is plaintext on localhost; `reveal_secret` sends credential
  plaintext to the client. Auth is a single shared password over an unencrypted
  socket — fine for `127.0.0.1` or a trusted LAN, but do **not** expose the port
  to an untrusted network. For remote use, tunnel it (SSH/WireGuard) rather than
  binding `0.0.0.0` on the open internet.
- Audio and a few polish widgets (shared toast stack, help overlay, map DSL)
  are not ported yet.

## Scanner-tool preflight, warning badge, and the background eye

On startup the daemon runs a **preflight** over the scanner binaries (nmap,
nuclei, wapiti): if one is missing and `[tools]auto_install` is on, it makes a
best-effort, non-interactive install attempt. Each tool's status streams to
clients as `ToolStatus` events (and is in `hello.tools`):

    ok / installed  green check    -- binary present
    installing      cyan           -- transient
    mock            amber warning  -- missing; the MCP server runs in mock mode
    error           red warning    -- install attempted and failed

The console's **SCANNER TOOLS** panel lists them (with a **recheck** button that
re-runs the preflight, `{"cmd":"recheck_tools"}`), and a **warning badge** in the
top bar lights when any tool is mock/error. Missing tools are a soft warning --
the matching server still works in mock mode.

The **RED eye** now renders as a large, dim, procedurally-textured lens **behind
the whole UI** (see `shaders/red_eye.gdshader` -- iris striations, concentric
rings, a hot aperture, a glass highlight and fresnel rim). It reacts to session
state (idle / thinking / speaking / alert) via `main.gd`, and is hidden on the
boot screen (which keeps its own power-on eye). None of this is verified against
a real Godot runtime yet.

## Engagement scope

The console's **SCOPE** panel (top of the right rail) lists the authorised
targets and lets you add/remove them (CIDR, IP, hostname/domain, or URL). Scope
is shared across all connected operators and persisted to `config.cfg`
`[scope]targets`; changes broadcast as `ScopeUpdated`.

Enforcement is server-side in `mgr.call`: any tool whose target/subnet/host/url
argument falls outside the scope is **blocked** (RED is also told the scope so it
stays inside it). An empty scope means unrestricted. The **inventory is the
exception** -- enumeration tools (`list_assets`/`list_hosts`/`list_resources`)
are never blocked, and every asset carries a binary **in/out-of-scope** flag
(auto-computed from its IP/host, re-computed when the scope changes, and
right-click-toggleable per asset in the inventory view).

## Correlation (read-time, vendor-agnostic)

Assets and findings arrive from many sources; correlation merges them into one
view **without touching the raw rows**. It keys off normalized fields every
source emits -- `ip`, `hostname`, and the native `resource_id` (the part after
`vendor:` in an asset id) -- never off vendor names, so having/not having any
particular product (CrowdStrike, some other EDR, nothing) changes nothing.

- **Assets** sharing any strong key are auto-merged (union-find). The
  identity keys are configurable in `config.cfg` `[correlate]keys`. Weak matches
  (same short hostname, different address) become **suggestions** you confirm or
  dismiss -- never auto-merged. Manual `merge`/`dismiss` decisions persist.
- **Findings** merge by (CVE-or-title, host), with the host canonicalized
  through the asset clusters -- so the same CVE on the same box reported by three
  tools collapses to one finding with three sources.

Inventory and Findings each have a **RAW <-> CORRELATED** toggle. Correlated rows
show a **SOURCES** column (cyan when >1 source corroborates) and a member count;
the inventory's **suggestions (N)** button lets you merge/dismiss weak matches.
The view is cached server-side and recomputed only when data, scope, or a
merge/dismiss decision changes (broadcast as `CorrelationUpdated`). RPCs:
`correlated_assets`, `correlated_findings`, `correlation_suggestions`,
`merge_assets`, `unmerge_assets`, `dismiss_suggestion`.

## Labels + batch operations

Group host+port endpoints under a **label** and run one tool against all of them
at once -- e.g. "the 14 boxes running the same portal," then probe every one with
the same credential.

- **Make a label** (inventory BATCH bar): type a filter query (`svc:nginx
  port:443`), a label name, and "label web endpoints" -- every matching web
  endpoint joins the label (`label_from_query`). Labels are shared and persist.
- **Run a batch**: pick a label, a tool (populated from what the servers expose),
  and optionally a vault credential, then RUN BATCH. The daemon expands the label
  to endpoints, injects the credential (username/password) if chosen, filters to
  in-scope endpoints, and fans the tool across them -- streaming
  `BatchStart` / `BatchProgress` / `BatchEnd` into the console. Findings from each
  target (e.g. a valid credential from the `http-probe` tool) land in the
  findings DB as usual.

Scope still applies per target, so a batch never touches out-of-scope endpoints.
The inventory's top **filter** box is a quick client-side view filter (the BATCH
query box uses the real filter DSL server-side). RPCs/commands: `list_labels`,
`label_from_query`, `label_endpoints`, `filter_endpoints`, `add_label_member`,
`remove_label`, and the `batch_run` command.

Two shortcuts in the BATCH bar make labelling one click: **auto-label** groups
every endpoint by service+port fingerprint and creates a label per group of 2+
(e.g. `auto/nginx:443` for all 14 nginx boxes), and **label like selected** (also
on the right-click menu as "label endpoints like this") labels every endpoint
running the same service on the same port as the selected host (`label_like`).

## Label deletion, richer filters, batch playbooks

- **Delete a label**: the inventory BATCH bar has a **del label** button
  (`remove_label`); single endpoints can be dropped with `remove_label_member`.
- **Filters** now accept glob wildcards (`svc:*nginx*`, `host:web0?`) and regex
  when slash-wrapped (`host:/^web\d+/`), in addition to plain substrings. Glob is
  anchored, so use `*x*` for substring. This applies anywhere the filter DSL is
  used (labeling, batch queries, map scoping).
- **Batch playbooks**: RUN BATCH can run *several* tools per endpoint. Pick a
  primary tool and/or type extra tools (comma-separated) in the playbook box
  (e.g. `probe, scan`); each runs against every endpoint in sequence.

## Exporting data + reports

The **Activity Log** view has an EXPORT bar:

- **report (HTML)** -- a self-contained, styled engagement report
  (`export_report_html`): summary cards, a severity bar, the engagement scope,
  findings (with the vendor **sources** that corroborate each), the inventory
  (out-of-scope rows dimmed), labels, and a redacted credential list. Open it in
  a browser and print-to-PDF for the deliverable.
- **report (PDF)** -- the same report as a PDF (`export_report_pdf`), rendered
  with the pure-Python `fpdf2` library (in requirements.txt). If it isn't
  installed on the backend the button reports that instead of failing.
- **report (MD)** -- the Markdown version (`export_report_md`).
- **inventory CSV** -- now includes `in_scope` and `labels` columns.
- **findings CSV** -- the *correlated* findings (`export_correlated_findings_csv`),
  so the same CVE across tools is one row with a `sources` column. Raw variants
  (`export_findings_csv`, `export_correlated_inventory_csv`, `export_labels_csv`,
  `export_vault_csv`) are also available.
- **full bundle** -- one click writes a timestamped `engagement_<ts>/` folder
  with every CSV (raw + correlated), the Markdown and HTML reports
  (`export_bundle`), and returns the folder path.

Files are written on the daemon host under `exports/`; the log shows the path of
each export. Credentials are always redacted in reports and in the default vault
export (`export_vault_csv` can reveal secrets only when explicitly asked).

## Change tracking, attack graph, approvals, new scanners, remote backend

- **Scan diffing** (Activity Log > TRACK): "take snapshot" saves the current
  inventory+findings; "diff vs latest" reports new/removed hosts, opened/closed
  ports, and new/resolved findings since. RPCs: `take_snapshot`, `list_snapshots`,
  `diff_snapshot`, `delete_snapshot`.
- **Attack graph** ("attack graph" button / `attack_graph` RPC): builds
  assets<->findings<->credentials and surfaces cred->asset->serious-finding
  chains.
- **Approval gate**: dangerous tools (name matches `[approval]dangerous` --
  probe/brute/spray/exploit/...) are blocked in `mgr.call` until armed in the
  console's **DANGEROUS TOOLS** panel (`arm_tool` / `list_approvals`). Composes
  with batch fan-out: arm once, run, disarm.
- **New scanner modules** (server + extractor each, mock-capable): `httpx`
  (web fingerprint -- makes auto-label group by real tech), `subfinder`
  (subdomains), `masscan` (fast sweep), `trivy` (image CVEs).
- **Report cover metadata**: `[engagement]` client/tester/window/contact (also
  `set_engagement`) render on the HTML and PDF reports.
- **Remote backend**: a BACKEND host:port field on the sign-in screen
  (`Backend.set_endpoint`) plus **download last** in the Activity Log, which
  pulls an export off the daemon over the socket (`fetch_export`, restricted to
  the exports dir) and saves it to the client's `user://` folder.

Backend logic (diffing, graph, approvals, reporting, scope, correlation, batch,
filters) is covered by `tests/test_redeye.py` -- run `pytest -q`.

## Attack surface map (F2)

The map view is a sci-fi threat display driven by `attack_graph`: concentric
radar rings place credentials (inner) -> assets (mid) -> findings (outer), with
glowing edges ("opens" in amber, "has" coloured by severity) and light pulses
travelling along the real cred -> asset -> finding attack chains. A rotating
radar sweep, hover-to-highlight (dims everything not connected to the node under
the cursor), and click-to-ask (click an asset or finding to send RED a directive
about it) round it out. It refreshes as the correlated view changes.

## Findings lifecycle, editable severity, richer reports, screenshots

- **Editable findings**: right-click a finding for **set severity** (CRITICAL..INFO)
  and **set status** (open / confirmed / remediated / accepted_risk /
  false_positive) submenus, or use the EDIT panel under the table to change the
  title, hosts, severity, status, CVSS, CWE, description, recommendation, and
  evidence -- all via `update_finding`, any time after the finding is created.
- **Report executive summary**: the HTML and PDF reports now open with a risk
  narrative (finding counts, overall posture, priority remediation targets).
- **Evidence + CVSS/CWE**: each finding's detail shows its CVSS/CWE and an
  evidence block (raw output / notes).
- **Screenshots**: the `gowitness` server captures a web screenshot (PNG); it's
  stored and embedded in a gallery in the HTML report. Trigger it via RED or a
  batch over a web label. (Mock renders a stylised frame offline; swap in a real
  headless-browser backend later without touching the pipeline.)

## One-click web screenshots + hover previews

- **screenshot web** button (Inventory batch bar): fans the `gowitness` tool
  across every in-scope web endpoint (or the selected label / query), captures a
  PNG each, and stores them. Uses `target_key=url` so the URL reaches the tool.
- **Hover previews**: hover a row in the Inventory (or an asset node on the
  Attack Map) and, if a screenshot exists for that host, a thumbnail pops up next
  to the cursor. Backed by `get_screenshot {host}`; decoded textures are cached
  client-side so repeat hovers are instant.

## UX polish

- **Screenshot badge**: inventory rows and attack-map asset nodes whose host has
  a stored screenshot show a small camera marker (driven by `list_screenshots`,
  refreshed live on `ScreenshotCaptured`), so you know what to hover. The map
  legend gains a "has screenshot" entry.
- **Header counts**: the Inventory / Findings / Key Vault headers show a live
  item count, e.g. "INVENTORY (37)".
- **Empty states**: empty tables show a dim hint ("no assets yet -- run a
  scan...", etc.) instead of a blank grid.
- **Enter to submit**: the add-finding and add-credential forms submit on Enter.
- The top bar already shows a live **LINK LIVE / LINK DOWN** connection pill.

## Screenshot gallery (F7)

A grid of every captured web screenshot, backed by the `gallery` RPC:
- **Filter** by label (uses the existing label system -- a screenshot inherits
  its host's labels) and by free-text (URL / status).
- **Sort** by recency, **HTTP status**, **visual similarity** (a nearest-
  neighbour chain over each capture's 64-bit average hash, so look-alike pages
  sit together -- handy for spotting the same default app across many hosts), or
  URL. Status is stored per capture (mocked deterministically offline) and each
  tile's caption is coloured by status class.
- **Click a tile** to enlarge; "ask RED about this endpoint" hands it to the
  console. The gallery refreshes live as new captures land.

## Recommended next steps panel

A **NEXT STEPS** button in the top bar opens a slide-in side panel (available on
any view) that reads the live engagement state and suggests what to do next,
grouped into three tracks: **BUILD INVENTORY**, **EXPLORE ENDPOINTS**, and
**SECURITY TESTING**. Each suggestion has a one-click action -- ask RED (a
directive), open a view, run a command (e.g. screenshot all web endpoints), or
call an action (auto-label, snapshot, generate report). The build-inventory track is ordered: **set the scope -> connect your tools ->
build out the inventory (discover hosts)**. Further examples: assets but no captures -> "Screenshot N web
endpoints"; web hosts but no findings -> "Run vulnerability scans"; untested
creds -> "Test N captured credentials"; findings present -> "Document findings".
The panel refreshes as state changes (`recommendations` RPC; logic in
`redeye/advisor.py`).

## Vulnerable version search (F8) + smarter advisor

- **F8 VERSIONS** is a cross-source software/version inventory: every product and
  version detected by any tool (nmap service/version strings, httpx tech+version,
  service banners) is aggregated into one searchable list, each row showing the
  version, how many hosts run it, which tools reported it, and any findings on
  those hosts. Builds with a related finding are flagged and sort to the top --
  that's your "likely-vulnerable versions" list. Search by product / version /
  host / source / CVE; double-click a row to ask RED to check it for known CVEs.
  Backed by the `components` RPC (logic in `redeye/components.py`).
- **Advisor now sees inventory + versions** and adds chained suggestions:
  "Investigate N flagged software builds" / "Hunt vulnerable versions" (opens
  F8), "Review N screenshots by similarity" (after captures land), and "Diff
  against your baseline" (once a snapshot exists).
- **Top-suggestion prompt**: the console shows a subtle "▸ suggested: ..." line
  with the #1 next step; clicking it runs that action (main dispatches it), so
  you get a nudge even with the NEXT STEPS panel closed.

## Tools & integrations (F10)

A settings tab for the available tools and their integration settings (URL,
username, API key, etc.). Non-sensitive values are saved to config; sensitive
values are stored in the encrypted **key vault** (F5) -- config keeps only a
`vault:<id>` reference, never the secret. Each secret field can either link an
existing vault entry or create a new one inline.

Tools that support it (AWS, Tenable, Wiz, CrowdStrike) can be added **multiple
times** -- e.g. two Tenable tenants or several AWS accounts -- each instance with
its own URL and its own vault-backed keys. Use the "add" dropdown to create an
instance and "remove" to delete one. Local scanner tools appear as single
entries. Backed by the `list_integrations` / `add_integration` /
`set_integration_field` / `save_integration_secret` / `link_integration_secret`
/ `remove_integration` RPCs; schemas + env resolution live in
`redeye/integrations.py`, instances in the `integrations` DB table.
