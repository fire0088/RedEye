"""Thread + async bridge.

The front-end runs in its own process (Godot). All slow / async work --
Bedrock inference, MCP tool calls -- runs on a single background thread that
owns an asyncio event loop. The two sides talk through thread-safe queues:

    UI  --(commands)-->  worker
    UI  <--(events)----  worker

Commands and events are plain dataclasses so there is zero shared mutable state
between threads.
"""
from __future__ import annotations

import asyncio
import queue
import threading
from dataclasses import dataclass, field
from typing import Any


# ===========================================================================
# Commands: UI -> worker
# ===========================================================================
@dataclass
class ListModels:
    profile: str
    region: str


@dataclass
class Connect:
    profile: str
    region: str
    model_id: str
    model_label: str = ""


@dataclass
class UserMessage:
    text: str


@dataclass
class CallToolDirect:
    """Fire a specific tool without going through the LLM (context-menu actions)."""
    tool: str
    args: dict
    note: str = ""


@dataclass
class Shutdown:
    pass


@dataclass
class BatchRun:
    """Fan one or more tools out across many endpoints (a label or filter).
    steps is a playbook: [{"tool", "target_key", "args"}] run per endpoint."""
    steps: list
    targets: list          # list of endpoint dicts, each with a "target"
    label: str = ""


# ===========================================================================
# Events: worker -> UI
# ===========================================================================
@dataclass
class Status:
    text: str


@dataclass
class Error:
    text: str
    fatal: bool = False


@dataclass
class ModelsList:
    models: list[dict]              # [{id, label, provider}]
    error: str = ""


@dataclass
class Connected:
    model_id: str
    model_label: str


@dataclass
class ServerStatus:
    key: str
    name: str
    category: str
    status: str
    color: tuple
    error: str = ""


@dataclass
class ServerTools:
    key: str
    tools: list[str]


@dataclass
class AssistantStart:
    pass


@dataclass
class AssistantDelta:
    text: str


@dataclass
class AssistantEnd:
    pass


@dataclass
class ToolStart:
    name: str
    server: str
    args: dict


@dataclass
class ToolEnd:
    name: str
    server: str
    result: str
    is_error: bool


@dataclass
class HostUpsert:
    """A discovered node for the network map. Fields mirror state.Host."""
    id: str
    label: str
    source: str
    kind: str = "host"
    ip: str = ""
    hostname: str = ""
    os: str = ""
    status: str = "up"
    ports: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    color: tuple = (120, 200, 255)


@dataclass
class VaultUpsert:
    """A credential/secret discovered by a scan, routed into the key vault."""
    kind: str = "secret"
    label: str = ""
    username: str = ""
    secret: str = ""
    scope: str = ""
    source: str = ""            # filled by extract() with the server key
    notes: str = ""


@dataclass
class FindingUpsert:
    """A finding produced by a scanner (nuclei, wapiti, ...), routed into the
    findings DB. `dedupe` keeps re-scans from creating duplicates."""
    dedupe: str
    title: str = "Untitled finding"
    severity: str = "MEDIUM"
    hosts: str = ""
    description: str = ""
    recommendation: str = ""
    source: str = ""            # filled by extract() with the server key


@dataclass
class ScreenshotUpsert:
    """A captured web screenshot (gowitness). image_b64 is a PNG."""
    url: str
    asset: str = ""
    title: str = ""
    image_b64: str = ""
    status: int = 0            # HTTP status code
    phash: str = ""            # 64-bit average hash (16 hex chars) for similarity


@dataclass
class Thinking:
    on: bool


@dataclass
class BatchStart:
    tool: str
    total: int
    label: str = ""


@dataclass
class BatchProgress:
    index: int
    total: int
    target: str
    ok: bool
    summary: str = ""


@dataclass
class BatchEnd:
    tool: str
    total: int
    ok: int
    fail: int
    label: str = ""


# ===========================================================================
# Bridge
# ===========================================================================
class Bridge:
    def __init__(self) -> None:
        self.cmds: "queue.Queue[Any]" = queue.Queue()
        self.events: "queue.Queue[Any]" = queue.Queue()
        self._thread: threading.Thread | None = None

    # -- called from UI thread ---------------------------------------------
    def send(self, cmd: Any) -> None:
        self.cmds.put(cmd)

    def drain(self) -> list[Any]:
        out = []
        try:
            while True:
                out.append(self.events.get_nowait())
        except queue.Empty:
            pass
        return out

    # -- called from worker -------------------------------------------------
    def emit(self, event: Any) -> None:
        self.events.put(event)

    # -- lifecycle ----------------------------------------------------------
    def start(self, config: dict) -> None:
        from .worker import worker_main
        self._thread = threading.Thread(
            target=lambda: asyncio.run(worker_main(self, config)),
            name="redeye-worker",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self.send(Shutdown())
        if self._thread:
            self._thread.join(timeout=4.0)
