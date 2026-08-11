"""Approval gate for dangerous actions.

Scope answers *where* you may act; this answers *what*. Tools whose name matches
a "dangerous" pattern (credential spray, brute force, exploit, ...) are blocked
in MCPManager.call until an operator explicitly ARMS them for the session. This
is deliberately a session-scoped allow, not a per-call prompt, so it composes
with batch fan-out: arm the tool once, run the batch, disarm.
"""
from __future__ import annotations

import threading

DEFAULT_PATTERNS = ["brute", "spray", "exploit", "probe", "attack", "login",
                    "password", "cred", "shell", "rce", "inject"]


class Approvals:
    def __init__(self, patterns=None):
        pats = patterns if patterns is not None else DEFAULT_PATTERNS
        self.patterns = [str(p).strip().lower() for p in pats if str(p).strip()]
        self._armed: set = set()
        self._lock = threading.Lock()

    def is_dangerous(self, tool) -> bool:
        t = str(tool).lower()
        return any(p in t for p in self.patterns)

    def allowed(self, tool) -> bool:
        if not self.is_dangerous(tool):
            return True
        with self._lock:
            return tool in self._armed

    def arm(self, tool, on: bool = True) -> None:
        with self._lock:
            if on:
                self._armed.add(tool)
            else:
                self._armed.discard(tool)

    def armed(self) -> list:
        with self._lock:
            return sorted(self._armed)

    def status(self) -> dict:
        return {"patterns": list(self.patterns), "armed": self.armed()}
