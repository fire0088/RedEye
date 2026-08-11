"""REDEYE backend regression suite -- pure logic, no sockets. Run: pytest -q"""
import json
import pytest
from redeye import (scope as SC, correlate as CO, batch as BA, filters as FI,
                    reporting as RE, diffing as DI, graph as GR, approvals as AP)


# ---- scope ----
def test_scope_matching():
    s = SC.Scope(["10.0.0.0/24", "*.corp.example.com", "203.0.113.5"])
    assert s.in_scope("10.0.0.9")
    assert not s.in_scope("10.0.1.9")
    assert s.in_scope("web.corp.example.com")
    assert not s.in_scope("evil.com")
    assert s.in_scope("https://app.corp.example.com/x")
    assert SC.Scope([]).in_scope("8.8.8.8")  # empty = unrestricted

def test_scope_check_args():
    s = SC.Scope(["10.0.0.0/24"])
    assert s.check_args({"target": "8.8.8.8"}) == (False, "8.8.8.8")
    assert s.check_args({"subnet": "10.0.0.0/24"})[0]
    assert s.check_args({"profile": "prod"})[0]  # non-target arg ignored


# ---- correlation ----
def _asset(i, ip="", host="", svc="", port=None, src="nmap"):
    ports = [{"port": port, "state": "open", "service": svc}] if port else []
    return {"id": f"{src}:{i}", "label": i, "kind": "host", "source": src,
            "ip": ip, "hostname": host, "in_scope": 1,
            "ports_json": json.dumps(ports), "meta_json": "{}"}

def test_correlate_merges_sources():
    rows = [_asset("web", ip="10.0.0.11", src="nmap"),
            {"id": "aws:i-1", "label": "web", "source": "aws", "ip": "10.0.0.11",
             "hostname": "h.ec2", "kind": "server", "in_scope": 1,
             "ports_json": "[]", "meta_json": '{"vendor":"aws"}'}]
    res = CO.correlate_assets(rows)
    assert len(res["assets"]) == 1
    assert set(res["assets"][0]["sources"]) == {"nmap", "aws"}

def test_correlate_suggest_and_merge():
    rows = [_asset("a", ip="10.0.0.5", host="web01.corp"),
            _asset("b", ip="10.0.5.9", host="web01.dr", src="edr")]
    res = CO.correlate_assets(rows)
    assert len(res["assets"]) == 2 and len(res["suggestions"]) == 1
    merged = CO.correlate_assets(rows, merges=[("nmap:a", "edr:b")])
    assert len(merged["assets"]) == 1

def test_correlate_findings_dedup():
    assets = CO.correlate_assets([_asset("web", ip="10.0.0.11", host="h.ec2")])["assets"]
    finds = [{"id": 1, "title": "CVE-2024-3094", "severity": "CRITICAL",
              "hosts": "10.0.0.11", "source": "scan:aws", "status": "open"},
             {"id": 2, "title": "CVE-2024-3094", "severity": "CRITICAL",
              "hosts": "h.ec2", "source": "scan:wiz", "status": "open"}]
    merged = CO.correlate_findings(finds, assets)
    assert len(merged) == 1 and set(merged[0]["sources"]) == {"aws", "wiz"}


# ---- batch / fingerprint ----
def test_endpoints_web_vs_host():
    rows = [_asset("w", ip="10.0.0.5", svc="https/nginx", port=443),
            _asset("d", ip="10.0.0.7", svc="postgres", port=5432)]
    web = BA.endpoints_for_rows(rows, "", "web")
    assert [e["target"] for e in web] == ["https://10.0.0.5"]
    assert len(BA.endpoints_for_rows(rows, "", "host")) == 2

def test_auto_group_and_like():
    rows = [_asset(f"h{i}", ip=f"10.0.0.{i}", svc="https/nginx", port=443)
            for i in range(1, 4)]
    rows.append(_asset("x", ip="10.0.0.9", svc="postgres", port=5432))
    groups = BA.auto_group(rows, "web", 2)
    assert groups and groups[0]["label"] == "auto/nginx:443" and groups[0]["count"] == 3
    sig, eps, label = BA.endpoints_like(rows, "nmap:h1")
    assert sig == "nginx:443" and len(eps) == 3

def test_service_family():
    assert BA.service_family("https/nginx 1.24") == "nginx"
    assert BA.service_family("OpenSSH 8.9p1") == "openssh"


# ---- filters ----
class _H:
    def __init__(self, **k):
        self.__dict__.update(k); self.meta = k.get("meta", {})

def _sel(hosts, q):
    return [h.hostname for h in hosts if FI.match(h, FI.compile_query(q))]

def test_filters_glob_regex():
    hosts = [_H(ip="10.0.0.5", hostname="web01.corp", label="web01", os="linux",
                status="up", kind="host", source="nmap",
                ports=[{"port": 443, "state": "open", "service": "https/nginx"}]),
             _H(ip="10.0.0.6", hostname="db01.corp", label="db01", os="linux",
                status="up", kind="host", source="nmap",
                ports=[{"port": 5432, "state": "open", "service": "postgres"}])]
    assert _sel(hosts, "host:web0*") == ["web01.corp"]
    assert _sel(hosts, r"host:/^web\d+/") == ["web01.corp"]
    assert _sel(hosts, "svc:*nginx*") == ["web01.corp"]
    assert _sel(hosts, "-svc:nginx") == ["db01.corp"]


# ---- reporting ----
def _ctx():
    return {"title": "T", "generated": "now", "scope": ["10.0.0.0/24"],
            "engagement": {"client": "Acme"}, "sev_counts": {"CRITICAL": 1},
            "findings": [{"severity": "CRITICAL", "title": "xz", "hosts": "web",
                          "status": "open", "sources": ["aws", "wiz"],
                          "description": "d", "recommendation": "r"}],
            "assets": [{"label": "web", "ip": "10.0.0.11", "kind": "server",
                        "open_count": 2, "sources": ["nmap"], "in_scope": 1}],
            "labels": [{"label": "auto/nginx:443", "count": 3}],
            "vault": [{"kind": "credential", "username": "admin", "scope": "web",
                       "status": "valid"}],
            "counts": {"findings_total": 1, "assets_total": 1, "vault_total": 1}}

def test_html_report():
    h = RE.html_report(_ctx())
    assert "Acme" in h and "aws, wiz" in h and "10.0.0.0/24" in h

def test_correlated_csv_rows():
    hdr, rows = RE.correlated_findings_rows(_ctx()["findings"])
    assert "sources" in hdr and rows[0][4] == "aws, wiz"

@pytest.mark.skipif(not RE.PDF_AVAILABLE, reason="fpdf2 not installed")
def test_pdf_report():
    data = RE.pdf_report(_ctx())
    assert data[:5] == b"%PDF-" and b"%%EOF" in data[-32:]


# ---- diffing ----
def test_diff():
    old = DI.make_snapshot(
        [{"id": "h1", "label": "a", "ip": "10.0.0.5",
          "ports_json": '[{"port":22,"state":"open"}]'}],
        [{"title": "CVE-2020-1", "hosts": "10.0.0.5", "severity": "HIGH"}])
    new = DI.make_snapshot(
        [{"id": "h1", "label": "a", "ip": "10.0.0.5",
          "ports_json": '[{"port":22,"state":"open"},{"port":443,"state":"open"}]'},
         {"id": "h2", "label": "b", "ip": "10.0.0.6", "ports_json": "[]"}],
        [{"title": "CVE-2024-3094", "hosts": "10.0.0.5", "severity": "CRITICAL"}])
    d = DI.diff(old, new)
    assert d["summary"] == {"new_hosts": 1, "removed_hosts": 0, "port_changes": 1,
                            "new_findings": 1, "resolved_findings": 1}
    assert d["port_changes"][0]["opened"] == [443]


# ---- graph ----
def test_graph_chain():
    assets = [{"label": "web01", "ip": "10.0.0.11", "hostname": "web01.corp",
               "ips": ["10.0.0.11"], "kind": "server", "in_scope": 1,
               "sources": ["nmap"]}]
    finds = [{"title": "CVE-2024-3094", "hosts": "10.0.0.11", "severity": "CRITICAL",
              "sources": ["aws"]}]
    vault = [{"id": 1, "username": "admin", "kind": "credential",
              "scope": "web01.corp", "status": "valid"}]
    g = GR.build_graph(assets, finds, vault)
    assert g["counts"]["chains"] == 1
    assert g["chains"][0]["asset"] == "web01"


# ---- approvals ----
def test_approvals():
    a = AP.Approvals()
    assert a.is_dangerous("http-probe") and not a.is_dangerous("scan")
    assert not a.allowed("probe")
    a.arm("probe", True)
    assert a.allowed("probe") and a.allowed("scan")


# ---- new: correlation carries cvss/cwe/evidence ----
def test_correlate_carries_cvss_cwe_evidence():
    from redeye import correlate as CO
    assets = CO.correlate_assets([_asset("web", ip="10.0.0.11", host="h.ec2")])["assets"]
    finds = [{"id": 1, "title": "CVE-2024-3094", "severity": "HIGH", "hosts": "10.0.0.11",
              "source": "scan:aws", "status": "open", "cvss": "10.0", "cwe": "CWE-506",
              "evidence": "liblzma backdoored"}]
    merged = CO.correlate_findings(finds, assets)
    assert merged[0]["cvss"] == "10.0" and merged[0]["cwe"] == "CWE-506"
    assert merged[0]["evidence"] == "liblzma backdoored"


# ---- new: executive summary + evidence + screenshots in the report ----
def test_report_exec_summary_and_evidence():
    ctx = _ctx()
    ctx["findings"][0]["cvss"] = "10.0"
    ctx["findings"][0]["cwe"] = "CWE-506"
    ctx["findings"][0]["evidence"] = "proof-of-exploit output"
    ctx["screenshots"] = [{"url": "https://x", "image": "iVBORw0KGgo="}]
    h = RE.html_report(ctx)
    assert "Executive summary" in h and "CVSS 10.0" in h and "CWE-506" in h
    assert "proof-of-exploit output" in h
    assert "data:image/png;base64,iVBORw0KGgo=" in h and "Screenshots" in h


# ---- new: gowitness produces a valid PNG ----
def test_gowitness_png():
    import base64, sys
    sys.path.insert(0, "servers")
    import gowitness_server as GW
    import json as _j
    out = _j.loads(GW.screenshot("https://portal.corp"))
    img = base64.b64decode(out["screenshots"][0]["image_b64"])
    assert img[:8] == b"\x89PNG\r\n\x1a\n" and len(img) > 200


# ---- new: gallery filter/sort ----
def test_gallery_sort_and_filter():
    from redeye import gallery as GA
    shots = [
        {"url": "https://a", "status": 200, "phash": "0000000000000000", "created": 3, "labels": ["web"]},
        {"url": "https://b", "status": 404, "phash": "ffffffffffffffff", "created": 1, "labels": []},
        {"url": "https://c", "status": 200, "phash": "0000000000000001", "created": 2, "labels": ["web"]},
    ]
    assert [s["url"] for s in GA.sort_screenshots(shots, "recent")] == ["https://a", "https://c", "https://b"]
    assert [s["status"] for s in GA.sort_screenshots(shots, "status")] == [200, 200, 404]
    # similarity: a and c (near-identical hashes) end up adjacent, b (opposite) separated
    order = [s["url"] for s in GA.sort_screenshots(shots, "similarity")]
    assert abs(order.index("https://a") - order.index("https://c")) == 1
    # label filter
    assert [s["url"] for s in GA.filter_screenshots(shots, label="web")] == ["https://a", "https://c"]
    # query filter (status text)
    assert [s["url"] for s in GA.filter_screenshots(shots, query="404")] == ["https://b"]

def test_gallery_hamming():
    from redeye import gallery as GA
    assert GA.hamming("0000000000000000", "0000000000000001") == 1
    assert GA.hamming("0000000000000000", "ffffffffffffffff") == 64


# ---- new: advisor recommended next steps ----
def test_advisor_progression():
    from redeye import advisor as AD
    empty = AD.recommend({})
    titles = [r["title"] for r in empty]
    # ordered: scope -> connect tools -> build inventory
    assert titles[:3] == ["Define the engagement scope", "Connect your tools", "Discover live hosts"]
    # once web assets exist, explore + security tracks appear
    mid = AD.recommend({"scope_set": True, "assets": 3, "open_hosts": 3,
                        "web_hosts": 3, "web_without_shot": 3, "fingerprinted": 0,
                        "findings": 0, "vault_untested": 0, "labels": 0,
                        "snapshots": 0, "suggestions": 0})
    cats = {r["category"] for r in mid}
    assert cats == {"inventory", "explore", "security"}
    assert any(r["title"].startswith("Screenshot") for r in mid)
    # every rec has a dispatchable action kind
    for r in mid:
        assert r["action"]["kind"] in ("directive", "goto", "command", "rpc")

def test_advisor_credentials_and_report():
    from redeye import advisor as AD
    recs = AD.recommend({"scope_set": True, "assets": 5, "open_hosts": 5,
                         "web_hosts": 3, "web_without_shot": 0, "fingerprinted": 5,
                         "findings": 4, "vault_untested": 2, "labels": 3,
                         "snapshots": 1, "suggestions": 0})
    titles = [r["title"] for r in recs]
    assert any("credential" in t for t in titles)
    assert "Document findings" in titles


# ---- new: component/version aggregation ----
def test_parse_service():
    from redeye import components as CO
    assert CO.parse_service("https/nginx 1.24.0") == ("nginx", "1.24.0")
    assert CO.parse_service("OpenSSH 8.9p1 Ubuntu") == ("openssh", "8.9p1")
    assert CO.parse_service("http/apache") == ("apache", "")
    assert CO.parse_service("") == ("", "")

def test_build_components_and_vuln_flag():
    import json as _j
    from redeye import components as CO
    assets = [
        {"id": "a", "label": "web1", "source": "nmap",
         "ports_json": _j.dumps([{"port": 443, "state": "open", "service": "https/nginx 1.24.0"}]),
         "meta_json": "{}"},
        {"id": "b", "label": "web2", "source": "nmap",
         "ports_json": _j.dumps([{"port": 443, "state": "open", "service": "nginx 1.24.0"}]),
         "meta_json": "{}"},
        {"id": "c", "label": "app", "source": "httpx",
         "ports_json": "[]", "meta_json": _j.dumps({"tech": "apache", "version": "2.4.58"})},
    ]
    findings = [{"title": "CVE-2024-3094", "hosts": "web1", "severity": "CRITICAL"}]
    comps = CO.build_components(assets, findings)
    nginx = [c for c in comps if c["product"] == "nginx"][0]
    assert nginx["version"] == "1.24.0" and nginx["host_count"] == 2
    assert nginx["vuln"] and "CVE-2024-3094" in nginx["findings"]
    apache = [c for c in comps if c["product"] == "apache"][0]
    assert not apache["vuln"] and "httpx" in apache["sources"]
    # vuln components sort first
    assert comps[0]["vuln"]
    # search
    assert [c["product"] for c in CO.search_components(comps, "2.4")] == ["apache"]

def test_advisor_version_chain():
    from redeye import advisor as AD
    recs = AD.recommend({"scope_set": True, "assets": 3, "open_hosts": 3,
                         "web_hosts": 3, "web_without_shot": 0, "screenshots": 4,
                         "fingerprinted": 3, "findings": 1, "vault_untested": 0,
                         "labels": 2, "snapshots": 1, "suggestions": 0,
                         "components": 5, "versioned": 4, "flagged": 2})
    titles = [r["title"] for r in recs]
    assert any("flagged software" in t for t in titles)        # version awareness
    assert any("Review" in t and "similarity" in t for t in titles)  # gallery chain
    assert any("Diff against your baseline" == t for t in titles)    # snapshot chain


# ---- new: multi-instance tool integrations ----
def test_integration_schema_and_multiple():
    from redeye import integrations as IN
    assert IN.multiple("tenable") and IN.multiple("aws")
    assert not IN.multiple("nmap")
    sec = [f for f in IN.schema_for("tenable")["fields"] if IN.is_secret(f)]
    assert {f["key"] for f in sec} == {"access_key", "secret_key"}
    # scanner default schema
    assert IN.schema_for("nmap")["fields"][0]["key"] == "binary"

def test_integration_env_resolves_vault():
    from redeye import integrations as IN
    vals = {"base_url": "https://t", "access_key": "vault:7", "secret_key": "plain"}
    env = IN.resolve_env("tenable", vals, lambda vid: "REVEALED" if vid == "7" else "")
    assert env["TENABLE_URL"] == "https://t"
    assert env["TENABLE_ACCESS_KEY"] == "REVEALED"   # vault ref resolved
    assert env["TENABLE_SECRET_KEY"] == "plain"

def test_integration_instances_isolated(tmp_path):
    import json as _j
    from redeye.database import Store
    st = Store(str(tmp_path / "t.db"))
    a = st.add_integration("tenable-a", "tenable", "US")
    b = st.add_integration("tenable-b", "tenable", "EU")
    st.set_integration_field(a, "base_url", "https://us")
    st.set_integration_field(b, "base_url", "https://eu")
    st.set_integration_field(a, "access_key", "vault:1")
    assert st.get_integration(a)["config"]["base_url"] == "https://us"
    assert st.get_integration(b)["config"]["base_url"] == "https://eu"
    assert "access_key" not in st.get_integration(b)["config"]
    st.remove_integration(a)
    assert st.get_integration(a) is None and st.get_integration(b) is not None
