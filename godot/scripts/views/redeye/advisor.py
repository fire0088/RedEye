"""Recommended next steps.

A tiny rules engine over a snapshot of engagement state. It returns an ordered
list of suggested actions grouped into three tracks -- build inventory, explore
endpoints, and security testing -- each with an action the UI can dispatch
(ask RED a directive, navigate, run a command, or call an RPC). Pure and
testable; the daemon builds the state summary and calls recommend().
"""
from __future__ import annotations

INVENTORY = "inventory"
EXPLORE = "explore"
SECURITY = "security"


def recommend(st: dict) -> list:
    recs = []

    def add(cat, title, detail, action):
        recs.append({"category": cat, "title": title, "detail": detail,
                     "action": action})

    # -- build inventory (ordered: scope -> connect tools -> discover) --
    if not st.get("scope_set"):
        add(INVENTORY, "Define the engagement scope",
            "Set authorised targets so every tool stays in-bounds.",
            {"kind": "goto", "view": "console"})
    if st.get("servers_online", 0) == 0:
        add(INVENTORY, "Connect your tools",
            "Bring your scanner tools online so you can enumerate and test.",
            {"kind": "goto", "view": "console"})
    if st.get("assets", 0) == 0:
        add(INVENTORY, "Discover live hosts",
            "No assets yet. Enumerate subdomains and sweep the target range.",
            {"kind": "directive",
             "text": "Enumerate subdomains for the target domain and sweep the "
                     "in-scope range for live hosts, then add them to inventory."})
    if st.get("suggestions", 0) > 0:
        add(INVENTORY, "Review %d correlation suggestion(s)" % st["suggestions"],
            "Merge likely-duplicate assets seen across different tools.",
            {"kind": "goto", "view": "inventory"})
    if st.get("assets", 0) > 0 and st.get("snapshots", 0) == 0:
        add(INVENTORY, "Take a baseline snapshot",
            "Capture the current state so you can diff what changes later.",
            {"kind": "rpc", "name": "take_snapshot", "args": {"label": "baseline"},
             "toast": "baseline snapshot taken"})

    # -- explore endpoints --
    if st.get("assets", 0) > 0 and st.get("fingerprinted", 0) == 0:
        add(EXPLORE, "Fingerprint web services",
            "Detect tech / title / status with httpx to sharpen labels.",
            {"kind": "directive",
             "text": "Fingerprint the web services on all in-scope hosts with "
                     "httpx and record what you find."})
    if st.get("labels", 0) == 0 and st.get("web_hosts", 0) > 1:
        add(EXPLORE, "Auto-label endpoints by service",
            "Group similar endpoints (e.g. auto/nginx:443) for batch actions.",
            {"kind": "rpc", "name": "auto_label", "args": {"ports": "web", "min": 2},
             "toast": "grouped endpoints by service", "goto": "inventory"})
    if st.get("web_without_shot", 0) > 0:
        add(EXPLORE, "Screenshot %d web endpoint(s)" % st["web_without_shot"],
            "Capture how each web app looks, then review them in the gallery.",
            {"kind": "command",
             "payload": {"cmd": "batch_run", "tools": ["screenshot"],
                         "target_key": "url", "ports": "web"},
             "goto": "gallery"})
    # chain: captures exist -> review look-alikes to spot the common default app
    if st.get("web_without_shot", 0) == 0 and st.get("screenshots", 0) > 1:
        add(EXPLORE, "Review %d screenshots by similarity" % st["screenshots"],
            "Sort the gallery by similarity to spot the same default app reused "
            "across hosts.",
            {"kind": "goto", "view": "gallery"})

    # -- security testing --
    if st.get("web_hosts", 0) > 0 and st.get("findings", 0) == 0:
        add(SECURITY, "Run vulnerability scans",
            "Scan the in-scope web endpoints with nuclei and wapiti.",
            {"kind": "directive",
             "text": "Run nuclei and wapiti against all in-scope web endpoints "
                     "and record any findings."})
    elif st.get("open_hosts", 0) > 0 and st.get("findings", 0) == 0:
        add(SECURITY, "Probe exposed services",
            "Hosts have open ports but no findings yet -- check for weak config.",
            {"kind": "directive",
             "text": "Review the exposed services on in-scope hosts and check "
                     "for weak or default configurations."})
    if st.get("vault_untested", 0) > 0:
        add(SECURITY, "Test %d captured credential(s)" % st["vault_untested"],
            "Attempt the captured credentials against their scoped targets.",
            {"kind": "directive",
             "text": "Test the captured credentials against their scoped targets "
                     "and mark which ones are valid."})
    if st.get("flagged", 0) > 0:
        add(SECURITY, "Investigate %d flagged software build(s)" % st["flagged"],
            "Components with findings on the same host -- likely vulnerable "
            "versions. Search and confirm.",
            {"kind": "goto", "view": "versions"})
    elif st.get("versioned", 0) > 0:
        add(SECURITY, "Hunt vulnerable versions (%d build(s))" % st["versioned"],
            "Software versions detected across sources -- search them for known "
            "CVEs.",
            {"kind": "goto", "view": "versions"})
    if st.get("findings", 0) > 0:
        add(SECURITY, "Document findings",
            "Generate the engagement report (exec summary, evidence, screenshots).",
            {"kind": "rpc", "name": "export_report_html",
             "toast": "report written", "goto": "log"})
    # chain: a baseline exists -> diff to catch drift after re-scanning
    if st.get("snapshots", 0) > 0 and st.get("assets", 0) > 0:
        add(INVENTORY, "Diff against your baseline",
            "See what hosts / ports / findings changed since your last snapshot.",
            {"kind": "goto", "view": "log"})

    if not recs:
        add(EXPLORE, "You're in good shape",
            "No urgent gaps detected. Keep exploring, or re-scan to catch changes.",
            {"kind": "goto", "view": "map"})
    return recs
