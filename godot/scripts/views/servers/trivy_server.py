#!/usr/bin/env python3
"""trivy-style container image CVE scanner MCP server (mock).

Given an image reference, returns CVE findings. Ships a deterministic mock.
"""
from __future__ import annotations
import hashlib, json
from mcp.server import MCPServer

srv = MCPServer("redeye-trivy")
_DB = [("CVE-2023-4911", "CRITICAL", "glibc Looney Tunables local privesc",
        "Upgrade glibc."),
       ("CVE-2024-3094", "CRITICAL", "xz-utils backdoor (liblzma)",
        "Downgrade xz to a known-good release."),
       ("CVE-2022-37434", "HIGH", "zlib heap overflow", "Upgrade zlib."),
       ("CVE-2021-3711", "HIGH", "OpenSSL SM2 buffer overflow", "Upgrade OpenSSL."),
       ("CVE-2023-0286", "MEDIUM", "OpenSSL X.400 type confusion", "Upgrade OpenSSL.")]


@srv.tool(description="Scan a container image for known CVEs. Returns findings.")
def scan_image(image: str) -> str:
    if not image:
        return json.dumps({"vendor": "trivy", "assets": [], "findings": []})
    h = int(hashlib.sha1(image.encode()).hexdigest(), 16)
    picks = [v for i, v in enumerate(_DB) if (h >> i) & 1] or _DB[:2]
    findings = [{"id": cve, "cve": cve, "severity": sev, "title": title,
                 "asset": image, "recommendation": rec,
                 "description": f"{cve} present in image {image}."}
                for (cve, sev, title, rec) in picks]
    return json.dumps({"vendor": "trivy", "mock": True,
                       "assets": [], "findings": findings})


if __name__ == "__main__":
    srv.run("stdio")
