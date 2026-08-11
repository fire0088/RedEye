"""Shared application state.

Single-writer discipline: the daemon serialises all writes behind one lock. The async
worker never touches these objects directly -- it emits events (see bridge.py)
and the main thread applies them here. That keeps everything lock-free.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Chat
# ---------------------------------------------------------------------------
@dataclass
class ToolCall:
    name: str
    server: str
    args: dict
    result: str = ""
    is_error: bool = False
    done: bool = False


@dataclass
class ChatMessage:
    role: str                       # "user" | "assistant" | "system"
    text: str = ""
    streaming: bool = False
    tools: list[ToolCall] = field(default_factory=list)
    ts: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Discovered nodes on the network map
# ---------------------------------------------------------------------------
@dataclass
class Host:
    id: str                         # stable identity, e.g. "nmap:10.0.0.5"
    label: str                      # what to draw
    source: str                     # server key that discovered it
    kind: str = "host"              # "host" | "endpoint" | "server"
    ip: str = ""
    hostname: str = ""
    os: str = ""
    status: str = "up"
    ports: list[dict] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    color: tuple[int, int, int] = (120, 200, 255)
    pos: tuple[float, float, float] = (0.0, 0.0, 0.0)
    discovered_at: float = field(default_factory=time.time)
    pulse: float = 1.0              # 1.0 -> fresh, decays; used for spawn glow


# ---------------------------------------------------------------------------
# MCP servers
# ---------------------------------------------------------------------------
@dataclass
class MCPServerInfo:
    key: str
    name: str
    category: str = "generic"
    transport: str = "stdio"
    status: str = "idle"            # idle|connecting|online|offline|error
    color: tuple[int, int, int] = (255, 60, 60)
    tools: list[str] = field(default_factory=list)
    error: str = ""
    pos: tuple[float, float, float] = (0.0, 0.0, 0.0)


# ---------------------------------------------------------------------------
# Top-level state
# ---------------------------------------------------------------------------
class AppState:
    def __init__(self) -> None:
        self.profile: str = ""
        self.region: str = ""
        self.model_id: str = ""
        self.model_label: str = ""

        self.chat: list[ChatMessage] = []
        self.hosts: dict[str, Host] = {}
        self.servers: dict[str, MCPServerInfo] = {}

        self.status_line: str = "STANDBY"
        self.thinking: bool = False           # LLM is generating
        self.speaking: bool = False           # streaming text right now
        self.connected: bool = False          # Bedrock session live

        self._server_ring_index = 0

    # -- chat helpers -------------------------------------------------------
    def add_user(self, text: str) -> ChatMessage:
        m = ChatMessage("user", text)
        self.chat.append(m)
        return m

    def begin_assistant(self) -> ChatMessage:
        m = ChatMessage("assistant", "", streaming=True)
        self.chat.append(m)
        return m

    def current_assistant(self) -> ChatMessage | None:
        for m in reversed(self.chat):
            if m.role == "assistant" and m.streaming:
                return m
        return None

    def add_system(self, text: str) -> None:
        self.chat.append(ChatMessage("system", text))

    # -- server helpers -----------------------------------------------------
    def upsert_server(self, info: MCPServerInfo) -> None:
        if info.key in self.servers:
            cur = self.servers[info.key]
            info.pos = cur.pos or info.pos
        if info.pos == (0.0, 0.0, 0.0):
            info.pos = self._next_server_pos()
        self.servers[info.key] = info

    def _next_server_pos(self) -> tuple[float, float, float]:
        # arrange server nodes on a ring in the XZ plane
        i = self._server_ring_index
        self._server_ring_index += 1
        radius = 26.0
        ang = i * (2 * math.pi / 6)  # 6 slots around the ring
        return (radius * math.cos(ang), 0.0, radius * math.sin(ang))

    # -- host helpers -------------------------------------------------------
    def upsert_host(self, host: Host) -> Host:
        existing = self.hosts.get(host.id)
        if existing:
            # merge: keep position, refresh dynamic fields
            host.pos = existing.pos
            host.discovered_at = existing.discovered_at
            if not host.ports and existing.ports:
                host.ports = existing.ports
        else:
            host.pos = self._place_near_source(host.source)
        host.pulse = 1.0
        self.hosts[host.id] = host
        return host

    def _place_near_source(self, source: str) -> tuple[float, float, float]:
        srv = self.servers.get(source)
        cx, cy, cz = srv.pos if srv else (0.0, 0.0, 0.0)
        # deterministic-ish scatter around the source cluster
        n = sum(1 for h in self.hosts.values() if h.source == source)
        ang = n * 2.399963  # golden angle for even spread
        r = 6.0 + 1.9 * math.sqrt(n + 1)
        y = ((n * 37) % 100 - 50) / 8.0
        return (cx + r * math.cos(ang), cy + y, cz + r * math.sin(ang))

    def decay_pulses(self, dt: float) -> None:
        for h in self.hosts.values():
            if h.pulse > 0:
                h.pulse = max(0.0, h.pulse - dt * 0.6)
