"""Attack-path / relationship graph.

Builds a graph over the correlated view: assets, findings, and vault
credentials, with edges for "asset has finding" and "credential opens asset".
It then walks credential -> asset -> serious-finding to surface concrete attack
chains. Pure function over plain data (the correlated assets/findings and the
vault list), so it's testable and vendor-agnostic.
"""
from __future__ import annotations

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _norm(s) -> str:
    return str(s or "").strip().lower().rstrip(".")


def build_graph(assets, findings, vault) -> dict:
    nodes, edges = [], []

    # asset nodes + a token index (ip / hostname / label -> node id)
    host_index = {}
    for a in assets:
        nid = "a:" + str(a.get("label") or a.get("id"))
        nodes.append({"id": nid, "type": "asset", "label": a.get("label", ""),
                      "kind": a.get("kind", ""), "in_scope": int(a.get("in_scope", 1)),
                      "sources": a.get("sources", [])})
        for tok in list(a.get("ips", [])) + [a.get("hostname"), a.get("ip"), a.get("label")]:
            if tok:
                host_index[_norm(tok)] = nid

    def _asset_for(host_str):
        h = _norm(host_str)
        if h in host_index:
            return host_index[h]
        for tok, nid in host_index.items():
            if tok and (tok in h or h in tok):
                return nid
        return None

    # finding nodes + "has" edges
    asset_findings = {}
    for i, f in enumerate(findings):
        fid = f"f:{i}"
        sev = str(f.get("severity", "")).upper()
        nodes.append({"id": fid, "type": "finding", "label": f.get("title", ""),
                      "severity": sev, "sources": f.get("sources", [])})
        aid = _asset_for(f.get("hosts", ""))
        if aid:
            edges.append({"source": aid, "target": fid, "kind": "has"})
            asset_findings.setdefault(aid, []).append((sev, f.get("title", "")))

    # credential nodes + "opens" edges (by scope/host token overlap)
    cred_assets = {}
    for c in vault:
        cid = f"c:{c.get('id')}"
        nodes.append({"id": cid, "type": "cred",
                      "label": c.get("username") or c.get("kind") or "credential",
                      "status": c.get("status", "")})
        scope = _norm(c.get("scope", ""))
        if not scope:
            continue
        for tok, nid in host_index.items():
            if tok and (scope in tok or tok in scope):
                if not any(e["source"] == cid and e["target"] == nid for e in edges):
                    edges.append({"source": cid, "target": nid, "kind": "opens"})
                    cred_assets.setdefault(cid, []).append(nid)

    # attack chains: cred -> asset -> serious finding
    node_label = {n["id"]: n["label"] for n in nodes}
    chains = []
    for cid, aids in cred_assets.items():
        for aid in aids:
            serious = [t for (sev, t) in asset_findings.get(aid, [])
                       if _SEV_RANK.get(sev, 0) >= 3]
            for t in serious:
                chains.append({
                    "cred": node_label.get(cid, ""),
                    "asset": node_label.get(aid, ""),
                    "finding": t,
                    "text": f"{node_label.get(cid,'')} -> {node_label.get(aid,'')} -> {t}",
                })

    return {"nodes": nodes, "edges": edges, "chains": chains,
            "counts": {"assets": sum(1 for n in nodes if n["type"] == "asset"),
                       "findings": sum(1 for n in nodes if n["type"] == "finding"),
                       "creds": sum(1 for n in nodes if n["type"] == "cred"),
                       "edges": len(edges), "chains": len(chains)}}
