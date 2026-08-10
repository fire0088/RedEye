"""Reporting: a self-contained HTML engagement report and CSV writers.

Pure functions over plain data (dicts/lists) so they're easy to test and don't
depend on the DB. The daemon gathers the data (raw + correlated view + scope +
labels) and hands it here. The HTML is standalone (inline CSS) -- open it in a
browser and print-to-PDF for the deliverable.
"""
from __future__ import annotations

import csv
import html
import time

try:
    from fpdf import FPDF          # fpdf2 (pure-Python, no system deps)
    PDF_AVAILABLE = True
except Exception:  # noqa: BLE001
    PDF_AVAILABLE = False

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_SEV_COLOR = {"CRITICAL": "#ff2d2d", "HIGH": "#ff6a00", "MEDIUM": "#ffb000",
              "LOW": "#46a0ff", "INFO": "#8a8a96"}


def _e(x) -> str:
    return html.escape(str(x if x is not None else ""))


def write_csv(path: str, header: list, rows: list) -> int:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        for r in rows:
            w.writerow(r)
    return len(rows)


# ---------------------------------------------------------------------------
# CSV row builders (correlation-aware)
# ---------------------------------------------------------------------------
def correlated_inventory_rows(assets: list):
    header = ["label", "ip", "hostname", "kind", "open_count", "sources",
              "source_count", "member_count", "in_scope"]
    rows = []
    for a in assets:
        rows.append([a.get("label", ""), a.get("ip", ""), a.get("hostname", ""),
                     a.get("kind", ""), a.get("open_count", 0),
                     ", ".join(a.get("sources", [])), a.get("source_count", 0),
                     a.get("member_count", 1),
                     "yes" if int(a.get("in_scope", 1)) else "no"])
    return header, rows


def correlated_findings_rows(findings: list):
    header = ["severity", "title", "hosts", "status", "sources",
              "source_count", "cve"]
    rows = []
    for f in findings:
        rows.append([f.get("severity", ""), f.get("title", ""),
                     f.get("hosts", ""), f.get("status", ""),
                     ", ".join(f.get("sources", [])), f.get("source_count", 0),
                     f.get("cve", "")])
    return header, rows


def labels_rows(labels: list):
    return ["label", "endpoint_count"], [[l.get("label", ""), l.get("count", 0)]
                                         for l in labels]


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------
def _sev_bar(sev_counts: dict, total: int) -> str:
    if total <= 0:
        return '<div class="muted">No findings recorded.</div>'
    seg = []
    for s in SEVERITIES:
        n = sev_counts.get(s, 0)
        if n:
            pct = 100.0 * n / total
            seg.append(f'<div class="seg" style="width:{pct:.1f}%;'
                       f'background:{_SEV_COLOR[s]}" title="{s}: {n}"></div>')
    legend = " ".join(
        f'<span class="pill" style="border-color:{_SEV_COLOR[s]}">'
        f'<b style="color:{_SEV_COLOR[s]}">{sev_counts.get(s,0)}</b> {s}</span>'
        for s in SEVERITIES)
    return f'<div class="bar">{"".join(seg)}</div><div class="legend">{legend}</div>'


def _exec_summary(findings, assets, sev_counts) -> str:
    total = len(findings)
    crit = sev_counts.get("CRITICAL", 0)
    high = sev_counts.get("HIGH", 0)
    in_scope_n = sum(1 for a in assets if int(a.get("in_scope", 1)))
    tops = [f for f in findings
            if str(f.get("severity", "")).upper() in ("CRITICAL", "HIGH")][:5]
    if total == 0:
        return "No findings were recorded during this engagement."
    parts = []
    risk = ("critical" if crit else "elevated" if high else "moderate")
    parts.append(f"This engagement identified <b>{total}</b> finding(s) across "
                 f"<b>{in_scope_n}</b> in-scope asset(s), representing a "
                 f"<b>{risk}</b> overall risk posture "
                 f"({crit} critical, {high} high).")
    if tops:
        names = "; ".join(_e(f.get("title", "")) for f in tops)
        parts.append(f"Priority remediation targets: {names}.")
    if crit:
        parts.append("Critical issues should be remediated immediately.")
    return " ".join(parts)


def html_report(ctx: dict) -> str:
    """ctx: {title, generated, scope[], sev_counts{}, findings[], assets[],
    labels[], vault[], counts{}}. findings/assets are the correlated view."""
    findings = ctx.get("findings", [])
    assets = ctx.get("assets", [])
    labels = ctx.get("labels", [])
    vault = ctx.get("vault", [])
    scope = ctx.get("scope", [])
    counts = ctx.get("counts", {})
    sev_counts = ctx.get("sev_counts", {})
    gen = ctx.get("generated", time.strftime("%Y-%m-%d %H:%M:%S"))
    title = ctx.get("title", "REDEYE engagement report")
    in_scope_assets = sum(1 for a in assets if int(a.get("in_scope", 1)))

    def card(label, value, sub=""):
        return (f'<div class="card"><div class="cval">{_e(value)}</div>'
                f'<div class="clab">{_e(label)}</div>'
                f'{f"<div class=cmuted>{_e(sub)}</div>" if sub else ""}</div>')

    # findings table + detail
    frows = ""
    for f in findings:
        sev = str(f.get("severity", "")).upper()
        srcs = ", ".join(f.get("sources", []))
        frows += (f'<tr><td><span class="sev" style="color:{_SEV_COLOR.get(sev,"#ccc")}">'
                  f'{_e(sev)}</span></td><td>{_e(f.get("title",""))}</td>'
                  f'<td>{_e(f.get("hosts",""))}</td><td>{_e(srcs)}</td>'
                  f'<td>{_e(f.get("status",""))}</td></tr>')
    fdetail = ""
    for f in findings:
        desc = str(f.get("description", "") or "").strip()
        rec = str(f.get("recommendation", "") or "").strip()
        if not (desc or rec):
            continue
        sev = str(f.get("severity", "")).upper()
        fdetail += (f'<div class="fd"><h3><span class="sev" '
                    f'style="color:{_SEV_COLOR.get(sev,"#ccc")}">{_e(sev)}</span> '
                    f'{_e(f.get("title",""))}</h3>'
                    f'<div class="muted">{_e(f.get("hosts",""))} · '
                    f'{_e(", ".join(f.get("sources", [])))}</div>')
        meta2 = []
        if f.get("cvss"):
            meta2.append("CVSS " + _e(f.get("cvss")))
        if f.get("cwe"):
            meta2.append(_e(f.get("cwe")))
        if f.get("status"):
            meta2.append("status: " + _e(f.get("status")))
        if meta2:
            fdetail += f'<div class="muted">{" · ".join(meta2)}</div>'
        if desc:
            fdetail += f"<p>{_e(desc)}</p>"
        if str(f.get("evidence", "") or "").strip():
            fdetail += f'<pre class="evi">{_e(str(f.get("evidence")).strip())}</pre>'
        if rec:
            fdetail += f'<p class="rec"><b>Recommendation:</b> {_e(rec)}</p>'
        fdetail += "</div>"

    # inventory table
    irows = ""
    for a in sorted(assets, key=lambda x: (0 if int(x.get("in_scope", 1)) else 1,
                                           x.get("label", ""))):
        insc = int(a.get("in_scope", 1))
        cls = "" if insc else ' class="oos"'
        irows += (f'<tr{cls}><td>{_e(a.get("label",""))}</td>'
                  f'<td>{_e(a.get("ip","") or a.get("hostname",""))}</td>'
                  f'<td>{_e(a.get("kind",""))}</td>'
                  f'<td>{_e(a.get("open_count",0))}</td>'
                  f'<td>{_e(", ".join(a.get("sources", [])))}</td>'
                  f'<td>{"in" if insc else "out"}</td></tr>')

    lrows = "".join(f'<tr><td>{_e(l.get("label",""))}</td>'
                    f'<td>{_e(l.get("count",0))}</td></tr>' for l in labels)
    vrows = "".join(f'<tr><td>{_e(v.get("kind",""))}</td>'
                    f'<td>{_e(v.get("username","") or "-")}</td>'
                    f'<td>{_e(v.get("scope","") or "-")}</td>'
                    f'<td>{_e(v.get("status",""))}</td></tr>' for v in vault)
    scope_html = (", ".join(_e(s) for s in scope) if scope
                  else '<span class="muted">unrestricted (no scope set)</span>')
    eng = ctx.get("engagement", {}) or {}
    eng_rows = "".join(
        f'<tr><td class="ek">{_e(k.title())}</td><td>{_e(eng.get(k,""))}</td></tr>'
        for k in ("client", "tester", "window", "contact") if eng.get(k))
    eng_html = (f'<table class="eng">{eng_rows}</table>' if eng_rows else "")
    exec_html = _exec_summary(findings, assets, sev_counts)
    shots = ctx.get("screenshots", [])
    shot_html = ""
    for sh in shots:
        img = sh.get("image", "") or sh.get("image_b64", "")
        if not img:
            continue
        shot_html += (f'<figure class="shot"><img src="data:image/png;base64,{img}"/>'
                      f'<figcaption>{_e(sh.get("url",""))}</figcaption></figure>')

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)}</title><style>
:root{{--bg:#0a0a0c;--panel:#141419;--ink:#e6e6ea;--muted:#8a8a96;--red:#ff2d2d;--line:#26262e}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;padding:32px}}
h1{{color:var(--red);margin:0 0 2px}} h2{{border-bottom:1px solid var(--line);
padding-bottom:6px;margin-top:34px}} .muted,.cmuted{{color:var(--muted)}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:10px;
padding:14px 18px;min-width:140px}} .cval{{font-size:26px;font-weight:700}}
.clab{{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}}
.bar{{display:flex;height:14px;border-radius:7px;overflow:hidden;background:#1e1e24;margin:10px 0}}
.seg{{height:100%}} .legend{{display:flex;gap:8px;flex-wrap:wrap}}
.pill{{border:1px solid var(--line);border-radius:20px;padding:2px 10px;font-size:12px}}
table{{width:100%;border-collapse:collapse;margin:10px 0;font-size:13px}}
th,td{{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--muted);font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.05em}}
tr.oos td{{color:var(--muted)}} .sev{{font-weight:700}}
.scopebox{{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 14px}}
.fd{{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--red);
border-radius:8px;padding:12px 16px;margin:12px 0}} .fd h3{{margin:0 0 4px}}
.rec{{color:#cfe}} footer{{margin-top:40px;color:var(--muted);font-size:12px}}
.eng{{width:auto;margin:12px 0;background:var(--panel);border:1px solid var(--line);border-radius:8px}}
.eng td{{border:none;padding:5px 14px}} .eng .ek{{color:var(--muted);text-transform:uppercase;font-size:11px}}
.exec{{background:#160a0a;border:1px solid #3a1414;border-left:3px solid var(--red);border-radius:8px;padding:12px 16px;margin:14px 0;line-height:1.55}}
.evi{{background:#0c0c11;border:1px solid var(--line);border-radius:6px;padding:8px 10px;white-space:pre-wrap;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:#b9c6d6;overflow-x:auto}}
.gallery{{display:flex;flex-wrap:wrap;gap:14px}} .shot{{margin:0;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:8px}}
.shot img{{display:block;width:320px;max-width:100%;border-radius:4px}} .shot figcaption{{color:var(--muted);font-size:11px;margin-top:6px;word-break:break-all}}
</style></head><body>
<h1>{_e(title)}</h1><div class="muted">Generated {_e(gen)}</div>
{eng_html}
<div class="exec"><b>Executive summary.</b> {exec_html}</div>
<div class="cards">
{card("Findings", counts.get("findings_total", len(findings)))}
{card("Assets", f'{in_scope_assets}/{counts.get("assets_total", len(assets))}', "in-scope / total")}
{card("Labels", len(labels))}
{card("Credentials", counts.get("vault_total", len(vault)))}
</div>
<h2>Severity</h2>{_sev_bar(sev_counts, sum(sev_counts.values()) if sev_counts else len(findings))}
<h2>Engagement scope</h2><div class="scopebox">{scope_html}</div>
<h2>Findings</h2>
{'<table><thead><tr><th>Sev</th><th>Title</th><th>Affected</th><th>Sources</th><th>Status</th></tr></thead><tbody>'+frows+'</tbody></table>' if findings else '<div class="muted">No findings recorded.</div>'}
{fdetail}
<h2>Inventory</h2>
{'<table><thead><tr><th>Label</th><th>IP / host</th><th>Kind</th><th>Open</th><th>Sources</th><th>Scope</th></tr></thead><tbody>'+irows+'</tbody></table>' if assets else '<div class="muted">No assets.</div>'}
<h2>Labels</h2>
{'<table><thead><tr><th>Label</th><th>Endpoints</th></tr></thead><tbody>'+lrows+'</tbody></table>' if labels else '<div class="muted">No labels.</div>'}
<h2>Credentials <span class="muted">(secrets redacted)</span></h2>
{'<table><thead><tr><th>Kind</th><th>Username</th><th>Scope</th><th>Status</th></tr></thead><tbody>'+vrows+'</tbody></table>' if vault else '<div class="muted">Vault empty.</div>'}
{('<h2>Screenshots</h2><div class="gallery">'+shot_html+'</div>') if shot_html else ''}
<footer>REDEYE · authorised engagement use only · secrets are never included in this report.</footer>
</body></html>"""


# ---------------------------------------------------------------------------
# PDF report (fpdf2 -- pure Python; optional)
# ---------------------------------------------------------------------------
_SEV_RGB = {"CRITICAL": (255, 45, 45), "HIGH": (255, 106, 0),
            "MEDIUM": (200, 140, 0), "LOW": (70, 160, 255), "INFO": (120, 120, 130)}
_INK = (30, 30, 34)
_MUTED = (130, 130, 150)
_RED = (200, 30, 30)


def _lat(s) -> str:
    """Core PDF fonts are latin-1 only; make any text safe to render."""
    return str(s if s is not None else "").encode("latin-1", "replace").decode("latin-1")


def pdf_report(ctx: dict) -> bytes:
    """Render the engagement report as a PDF (bytes). Raises RuntimeError if
    fpdf2 isn't installed."""
    if not PDF_AVAILABLE:
        raise RuntimeError("PDF support needs fpdf2 (pip install fpdf2)")

    findings = ctx.get("findings", [])
    assets = ctx.get("assets", [])
    labels = ctx.get("labels", [])
    vault = ctx.get("vault", [])
    scope = ctx.get("scope", [])
    counts = ctx.get("counts", {})
    sev_counts = ctx.get("sev_counts", {})
    gen = ctx.get("generated", time.strftime("%Y-%m-%d %H:%M:%S"))
    title = ctx.get("title", "REDEYE engagement report")
    in_scope_n = sum(1 for a in assets if int(a.get("in_scope", 1)))

    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(15, 15, 15)
    pdf.add_page()
    W = pdf.epw  # effective page width

    def h1(t):
        pdf.set_font("Helvetica", "B", 18)
        pdf.set_text_color(*_RED)
        pdf.cell(0, 10, _lat(t), new_x="LMARGIN", new_y="NEXT")

    def h2(t):
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(*_INK)
        pdf.cell(0, 8, _lat(t), new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(210, 210, 215)
        y = pdf.get_y()
        pdf.line(pdf.l_margin, y, pdf.l_margin + W, y)
        pdf.ln(2)

    def body(t, muted=False, size=10):
        pdf.set_font("Helvetica", "", size)
        pdf.set_text_color(*(_MUTED if muted else _INK))
        pdf.multi_cell(0, 5, _lat(t), new_x="LMARGIN", new_y="NEXT")

    h1(title)
    body(f"Generated {gen}", muted=True)
    eng = ctx.get("engagement", {}) or {}
    eng_lines = [f"{k.title()}: {eng[k]}" for k in
                 ("client", "tester", "window", "contact") if eng.get(k)]
    if eng_lines:
        pdf.ln(1)
        body("    ".join(eng_lines), muted=True)

    h2("Summary")
    body(f"Findings: {counts.get('findings_total', len(findings))}    "
         f"Assets: {in_scope_n}/{counts.get('assets_total', len(assets))} in-scope    "
         f"Labels: {len(labels)}    Credentials: {counts.get('vault_total', len(vault))}")
    import re as _re
    exec_txt = _re.sub("<[^>]+>", "", _exec_summary(findings, assets, sev_counts))
    body(exec_txt)
    # severity legend line, coloured
    pdf.set_font("Helvetica", "B", 10)
    for s in SEVERITIES:
        pdf.set_text_color(*_SEV_RGB[s])
        pdf.cell(pdf.get_string_width(f"{sev_counts.get(s,0)} {s}  ") + 2,
                 6, _lat(f"{sev_counts.get(s,0)} {s}"), new_x="RIGHT", new_y="TOP")
    pdf.ln(8)

    h2("Engagement scope")
    body(", ".join(scope) if scope else "unrestricted (no scope set)",
         muted=not scope)

    h2("Findings")
    if findings:
        for f in findings:
            sev = str(f.get("severity", "")).upper()
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(*_SEV_RGB.get(sev, _INK))
            pdf.multi_cell(0, 6, _lat(f"[{sev}] {f.get('title','')}"),
                           new_x="LMARGIN", new_y="NEXT")
            meta = f"{f.get('hosts','')}"
            srcs = ", ".join(f.get("sources", []))
            if srcs:
                meta += f"   sources: {srcs}"
            meta += f"   status: {f.get('status','')}"
            body(meta, muted=True, size=9)
            metab = []
            if f.get("cvss"):
                metab.append("CVSS " + str(f.get("cvss")))
            if f.get("cwe"):
                metab.append(str(f.get("cwe")))
            if metab:
                body("   ".join(metab), muted=True, size=9)
            if str(f.get("description", "") or "").strip():
                body(str(f["description"]).strip())
            if str(f.get("evidence", "") or "").strip():
                pdf.set_font("Courier", "", 8)
                pdf.set_text_color(90, 100, 120)
                pdf.multi_cell(0, 4, _lat(str(f["evidence"]).strip()),
                               new_x="LMARGIN", new_y="NEXT")
            if str(f.get("recommendation", "") or "").strip():
                pdf.set_font("Helvetica", "B", 10)
                pdf.set_text_color(*_INK)
                pdf.multi_cell(0, 5, _lat("Recommendation: ")
                               + _lat(str(f["recommendation"]).strip()),
                               new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
    else:
        body("No findings recorded.", muted=True)

    h2("Inventory")
    if assets:
        widths = [W * 0.28, W * 0.22, W * 0.16, W * 0.10, W * 0.24]
        heads = ["Label", "IP / host", "Kind", "Open", "Sources"]
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*_MUTED)
        for wdt, hd in zip(widths, heads):
            pdf.cell(wdt, 6, _lat(hd), border="B")
        pdf.ln(6)
        pdf.set_font("Helvetica", "", 9)
        for a in sorted(assets, key=lambda x: (0 if int(x.get("in_scope", 1)) else 1,
                                               x.get("label", ""))):
            insc = int(a.get("in_scope", 1))
            pdf.set_text_color(*(_INK if insc else _MUTED))
            cells = [str(a.get("label", "")),
                     str(a.get("ip", "") or a.get("hostname", "")),
                     str(a.get("kind", "")), str(a.get("open_count", 0)),
                     ", ".join(a.get("sources", [])) + ("" if insc else "  (oos)")]
            for wdt, cval in zip(widths, cells):
                pdf.cell(wdt, 5, _lat(_trunc(cval, wdt, pdf)), border="B")
            pdf.ln(5)
    else:
        body("No assets.", muted=True)

    if labels:
        h2("Labels")
        for l in labels:
            body(f"- {l.get('label','')}  ({l.get('count',0)} endpoints)")

    h2("Credentials (secrets redacted)")
    if vault:
        for v in vault:
            body(f"- {v.get('kind','')}: {v.get('username','') or '-'}  "
                 f"scope={v.get('scope','') or '-'}  status={v.get('status','')}")
    else:
        body("Vault empty.", muted=True)

    pdf.ln(4)
    body("REDEYE - authorised engagement use only - secrets are never included "
         "in this report.", muted=True, size=8)
    return bytes(pdf.output())


def _trunc(s: str, width_mm: float, pdf) -> str:
    s = str(s)
    if pdf.get_string_width(s) <= width_mm - 2:
        return s
    while s and pdf.get_string_width(s + "...") > width_mm - 2:
        s = s[:-1]
    return s + "..."
