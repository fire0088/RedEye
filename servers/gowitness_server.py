#!/usr/bin/env python3
"""gowitness-style web screenshot MCP server for REDEYE.

Captures a screenshot of a URL and returns it (base64 PNG) so it can be embedded
in the engagement report. Real gowitness drives a headless browser; that isn't
available here, so this renders a deterministic *mock* screenshot (a stylised
browser frame with the REDEYE eye) purely in Python -- proving the capture ->
store -> report pipeline. Swap in a real headless-browser backend later without
touching the extractor.
"""
from __future__ import annotations

import base64
import json
import struct
import zlib
from urllib.parse import urlparse

from mcp.server import MCPServer

srv = MCPServer("redeye-gowitness")

W, H = 320, 180


def _png(width, height, pixels: bytearray) -> bytes:
    """Encode an RGB pixel buffer (row-major, 3 bytes/px) as a PNG."""
    def chunk(typ, data):
        return (struct.pack(">I", len(data)) + typ + data
                + struct.pack(">I", zlib.crc32(typ + data) & 0xffffffff))
    raw = bytearray()
    stride = width * 3
    for y in range(height):
        raw.append(0)  # filter: none
        raw.extend(pixels[y * stride:(y + 1) * stride])
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
            + chunk(b"IEND", b""))


def _shot_buffer(url: str) -> bytearray:
    import hashlib
    seed = int(hashlib.sha1(url.encode()).hexdigest(), 16)
    buf = bytearray(W * H * 3)

    def px(x, y, r, g, b):
        if 0 <= x < W and 0 <= y < H:
            i = (y * W + x) * 3
            buf[i], buf[i + 1], buf[i + 2] = r, g, b

    # background
    for y in range(H):
        for x in range(W):
            px(x, y, 10, 8, 14)
    # top browser bar
    for y in range(0, 18):
        for x in range(W):
            px(x, y, 28, 20, 30)
    for k in range(3):  # traffic-light dots
        for dy in range(-3, 4):
            for dx in range(-3, 4):
                if dx * dx + dy * dy <= 9:
                    px(8 + k * 12 + dx, 9 + dy, 90, 60, 70)
    # header block (a coloured hero region whose tint varies per site)
    hr, hg, hb = 30 + seed % 90, 30 + (seed >> 8) % 90, 40 + (seed >> 16) % 90
    for y in range(24, 38):
        for x in range(20, W - 90):
            px(x, y, hr, hg, hb)
    # content lines (widths vary per site so similar pages hash alike)
    for row, ln in enumerate(range(46, 150, 16)):
        wdt = W - 40 - ((row * 17 + (seed >> row) % 90)) % 150
        for x in range(20, 20 + max(20, wdt)):
            for y in range(ln, ln + 4):
                px(x, y, 40, 40, 50)
    # the RED eye
    cx, cy, rad = W - 54, 96, 26
    for y in range(cy - rad, cy + rad):
        for x in range(cx - rad, cx + rad):
            d = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
            if d <= rad:
                t = 1.0 - d / rad
                px(x, y, int(120 + 135 * t), int(20 + 40 * t), int(20 + 30 * t))
            if abs(d - rad) < 1.4:
                px(x, y, 255, 60, 60)
    return buf


def _mock_status(url: str) -> int:
    import hashlib
    h = int(hashlib.sha1(url.encode()).hexdigest(), 16)
    return [200, 200, 200, 200, 301, 302, 403, 404, 500][h % 9]


def _ahash(buf: bytearray, width: int, height: int) -> str:
    """8x8 average hash over the RGB buffer -> 16 hex chars (64 bits)."""
    vals = []
    for gy in range(8):
        for gx in range(8):
            x = int((gx + 0.5) * width / 8)
            y = int((gy + 0.5) * height / 8)
            i = (y * width + x) * 3
            vals.append((buf[i] + buf[i + 1] + buf[i + 2]) // 3)
    avg = sum(vals) / len(vals)
    bits = 0
    for v in vals:
        bits = (bits << 1) | (1 if v >= avg else 0)
    return f"{bits:016x}"


@srv.tool(description="Capture a screenshot of a web URL (PNG). The image is "
                      "stored and embedded in the engagement report and gallery.")
def screenshot(url: str) -> str:
    if not url:
        return json.dumps({"vendor": "gowitness", "screenshots": []})
    if "://" not in url:
        url = "http://" + url
    host = urlparse(url).hostname or url
    buf = _shot_buffer(url)
    shot = {"url": url, "asset": host, "title": f"{host} (mock capture)",
            "status": _mock_status(url), "phash": _ahash(buf, W, H),
            "image_b64": base64.b64encode(_png(W, H, buf)).decode("ascii")}
    return json.dumps({"vendor": "gowitness", "mock": True, "screenshots": [shot]})


if __name__ == "__main__":
    srv.run("stdio")
