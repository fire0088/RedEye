"""Turn a finding into something you can act on outside REDEYE:

- a standalone Python proof-of-concept script you can run to manually retest, and
- a Jira issue -- created live if [jira] is configured in config.cfg, otherwise
  written to a JSON payload file you can import or POST yourself.

Nothing here needs the rest of the app; a finding is passed in as a plain dict
(dict(sqlite_row)).
"""
from __future__ import annotations

import base64
import json
import os
import re
import time
import urllib.error
import urllib.request

SEVERITY_PRIORITY = {
    "CRITICAL": "Highest", "HIGH": "High", "MEDIUM": "Medium",
    "LOW": "Low", "INFO": "Lowest",
}

_URL_RE = re.compile(r"https?://[^\s,]+")


def target_of(finding: dict) -> str:
    """Best-effort target from a finding's hosts field (first URL or token)."""
    hosts = (finding.get("hosts") or "").strip()
    m = _URL_RE.search(hosts)
    if m:
        return m.group(0)
    return hosts.split(",")[0].strip() if hosts else ""


def _slug(s: str, n: int = 40) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "_", s or "finding").strip("_").lower()
    return (s[:n] or "finding")


# ---------------------------------------------------------------------------
# Python proof-of-concept
# ---------------------------------------------------------------------------
def python_poc(finding: dict) -> str:
    target = target_of(finding)
    is_url = target.startswith(("http://", "https://"))
    title = finding.get("title", "finding")
    sev = finding.get("severity", "MEDIUM")
    hosts = finding.get("hosts", "")
    desc = (finding.get("description", "") or "").strip()
    rec = (finding.get("recommendation", "") or "").strip()
    fid = finding.get("id", "?")
    src = finding.get("source", "manual")
    header = (
        f'"""REDEYE proof-of-concept -- finding #{fid}\n'
        f"Title:       {title}\n"
        f"Severity:    {sev}\n"
        f"Source:      {src}\n"
        f"Target(s):   {hosts}\n\n"
        f"Description:\n  {desc or '(none)'}\n\n"
        f"Recommendation:\n  {rec or '(none)'}\n\n"
        f"Generated {time.strftime('%Y-%m-%d %H:%M:%S')}. Only run against\n"
        f"systems you are authorised to test.\n"
        f'"""\n'
    )
    if is_url:
        body = f'''import sys
import requests

TARGET = {target!r}
TIMEOUT = 10
VERIFY_TLS = False   # engagement targets often use self-signed certs

requests.packages.urllib3.disable_warnings()


def probe():
    """Reproduce the observed condition. Fill in the assertion for this finding."""
    print(f"[*] GET {{TARGET}}")
    r = requests.get(TARGET, timeout=TIMEOUT, verify=VERIFY_TLS,
                     allow_redirects=True)
    print(f"[*] {{r.status_code}} {{len(r.content)}} bytes  "
          f"({{r.headers.get('Content-Type','?')}})")

    # --- retest logic -----------------------------------------------------
    # TODO: assert the vulnerable condition. Examples:
    #   assert r.status_code == 200, "resource not reachable"
    #   assert "index of" in r.text.lower(), "no directory listing"
    #   assert "DB_PASSWORD" in r.text, "secret not exposed"
    vulnerable = r.status_code == 200
    print("[+] VULNERABLE" if vulnerable else "[-] not reproduced")
    return vulnerable


if __name__ == "__main__":
    try:
        sys.exit(0 if probe() else 1)
    except Exception as e:  # noqa: BLE001
        print(f"[!] error: {{e}}")
        sys.exit(2)
'''
    else:
        host = target or "127.0.0.1"
        port = ""
        if ":" in host and not host.startswith("["):
            host, _, port = host.partition(":")
        body = f'''import socket
import sys

HOST = {host!r}
PORT = {int(port) if port.isdigit() else 0}   # set the service port to retest
TIMEOUT = 5


def probe():
    """Reproduce the observed condition against the host/service."""
    if not PORT:
        print("[!] set PORT to the service you want to retest")
        return False
    print(f"[*] connecting to {{HOST}}:{{PORT}}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        s.connect((HOST, PORT))
    except OSError as e:
        print(f"[-] closed/filtered: {{e}}")
        return False
    try:
        banner = s.recv(256)
        print(f"[*] banner: {{banner!r}}")
    except OSError:
        banner = b""
    finally:
        s.close()
    # TODO: assert the vulnerable condition for this finding.
    vulnerable = True
    print("[+] service reachable" if vulnerable else "[-] not reproduced")
    return vulnerable


if __name__ == "__main__":
    try:
        sys.exit(0 if probe() else 1)
    except Exception as e:  # noqa: BLE001
        print(f"[!] error: {{e}}")
        sys.exit(2)
'''
    return header + "\n" + body


def write_python_poc(export_dir: str, finding: dict) -> str:
    os.makedirs(export_dir, exist_ok=True)
    fid = finding.get("id", "x")
    path = os.path.join(export_dir, f"poc_{fid}_{_slug(finding.get('title',''))}.py")
    with open(path, "w", encoding="utf-8") as f:
        f.write(python_poc(finding))
    return path


# ---------------------------------------------------------------------------
# Jira
# ---------------------------------------------------------------------------
def _description_text(finding: dict) -> str:
    return (
        f"*Severity:* {finding.get('severity','')}\n"
        f"*Source:* {finding.get('source','manual')}\n"
        f"*Affected:* {finding.get('hosts','')}\n\n"
        f"h3. Description\n{finding.get('description','') or '(none)'}\n\n"
        f"h3. Recommendation\n{finding.get('recommendation','') or '(none)'}\n\n"
        f"_Filed from REDEYE finding #{finding.get('id','?')}._"
    )


def _adf(text: str) -> dict:
    """Minimal Atlassian Document Format wrapper (paragraph per line)."""
    content = []
    for line in text.split("\n"):
        content.append({"type": "paragraph",
                        "content": ([{"type": "text", "text": line}]
                                    if line else [])})
    return {"type": "doc", "version": 1, "content": content}


def jira_payload(finding: dict, project: str = "SEC",
                 issuetype: str = "Bug", adf: bool = True) -> dict:
    sev = (finding.get("severity") or "MEDIUM").upper()
    labels = ["redeye", f"sev-{sev.lower()}"]
    src = finding.get("source", "")
    if src and src != "manual":
        labels.append(src.replace(":", "-"))
    desc = _description_text(finding)
    return {
        "fields": {
            "project": {"key": project},
            "summary": f"[{sev}] {finding.get('title','Untitled finding')}"[:250],
            "description": _adf(desc) if adf else desc,
            "issuetype": {"name": issuetype},
            "priority": {"name": SEVERITY_PRIORITY.get(sev, "Medium")},
            "labels": labels,
        }
    }


def write_jira_payload(export_dir: str, finding: dict, project: str = "SEC") -> str:
    os.makedirs(export_dir, exist_ok=True)
    fid = finding.get("id", "x")
    path = os.path.join(export_dir, f"jira_{fid}_{_slug(finding.get('title',''))}.json")
    payload = jira_payload(finding, project=project, adf=True)
    payload["_readable_description"] = _description_text(finding)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return path


def jira_configured(cfg: dict) -> bool:
    return bool(cfg.get("base_url") and cfg.get("email") and cfg.get("token"))


def jira_create(finding: dict, cfg: dict) -> tuple[bool, str]:
    """POST an issue to Jira Cloud. cfg: {base_url, email, token, project}.
    Returns (ok, issue_key_or_error). Never raises."""
    if not jira_configured(cfg):
        return False, "jira not configured"
    base = cfg["base_url"].rstrip("/")
    project = cfg.get("project", "SEC")
    payload = jira_payload(finding, project=project, adf=True)
    data = json.dumps(payload).encode("utf-8")
    auth = base64.b64encode(f"{cfg['email']}:{cfg['token']}".encode()).decode()
    req = urllib.request.Request(
        f"{base}/rest/api/3/issue", data=data, method="POST",
        headers={"Authorization": f"Basic {auth}",
                 "Content-Type": "application/json",
                 "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        key = body.get("key", "")
        return (True, key) if key else (False, "no key in response")
    except urllib.error.HTTPError as e:
        try:
            msg = e.read().decode("utf-8")[:200]
        except Exception:  # noqa: BLE001
            msg = str(e)
        return False, f"HTTP {e.code}: {msg}"
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def browse_url(cfg: dict, key: str) -> str:
    base = (cfg.get("base_url") or "").rstrip("/")
    return f"{base}/browse/{key}" if base and key else ""
