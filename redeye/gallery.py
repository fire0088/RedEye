"""Screenshot gallery ordering + filtering.

Pure functions over screenshot dicts (each carries url, title, status, phash,
created, labels). Sorting supports recency, HTTP status, URL, and visual
*similarity* (a greedy nearest-neighbour chain over the 64-bit average hash, so
look-alike captures sit next to each other).
"""
from __future__ import annotations


def hamming(a: str, b: str) -> int:
    try:
        return bin(int(a, 16) ^ int(b, 16)).count("1")
    except Exception:  # noqa: BLE001
        return 64


def order_by_similarity(shots: list) -> list:
    remaining = list(shots)
    if not remaining:
        return []
    # start from the lowest hash for determinism
    remaining.sort(key=lambda s: str(s.get("phash", "")))
    out = [remaining.pop(0)]
    while remaining:
        cur = out[-1].get("phash", "")
        best_i, best_d = 0, 999
        for i, s in enumerate(remaining):
            d = hamming(cur, s.get("phash", ""))
            if d < best_d:
                best_d, best_i = d, i
        out.append(remaining.pop(best_i))
    return out


def sort_screenshots(shots: list, sort: str = "recent") -> list:
    if sort == "status":
        return sorted(shots, key=lambda s: (int(s.get("status", 0) or 0),
                                            str(s.get("url", ""))))
    if sort == "url":
        return sorted(shots, key=lambda s: str(s.get("url", "")).lower())
    if sort == "similarity":
        return order_by_similarity(shots)
    return sorted(shots, key=lambda s: s.get("created", 0), reverse=True)


def filter_screenshots(shots: list, label: str = "", query: str = "") -> list:
    q = str(query or "").strip().lower()
    out = []
    for s in shots:
        if label and label not in (s.get("labels") or []):
            continue
        if q:
            hay = f"{s.get('url','')} {s.get('title','')} {s.get('status','')}".lower()
            if q not in hay:
                continue
        out.append(s)
    return out
