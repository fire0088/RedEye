"""MCP connection manager.

Everything is driven by mcp_config.json. To add a new capability you add one
block to that file -- no code changes here. Each server is launched (stdio) or
attached (sse / streamable-http), its tools are discovered, and every tool is
routed back to the session that owns it.

Tool names are namespaced only on collision, so the model usually sees clean
names ("port_scan") but two servers exposing "scan" become "nmap.scan" /
"other.scan".
"""
from __future__ import annotations

import os
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


@dataclass
class ToolInfo:
    name: str                # name exposed to the LLM (possibly namespaced)
    raw_name: str            # name on the server
    server_key: str
    description: str
    input_schema: dict


@dataclass
class ServerConn:
    key: str
    name: str
    category: str
    color: tuple
    extractor: str = ""
    status: str = "idle"
    error: str = ""
    session: Any = None
    tools: list[ToolInfo] = field(default_factory=list)


# inventory-enumeration tools are exempt from scope enforcement -- you may
# enumerate everything; each asset is flagged in/out of scope instead.
SCOPE_EXEMPT_TOOLS = {"list_assets", "list_hosts", "list_resources"}


class MCPManager:
    def __init__(self, servers_cfg: dict, base_dir: str, scope=None,
                 approvals=None) -> None:
        self.cfg = servers_cfg
        self.base_dir = base_dir
        self.scope = scope
        self.approvals = approvals
        self.stack = AsyncExitStack()
        self.conns: dict[str, ServerConn] = {}
        self.tool_route: dict[str, ToolInfo] = {}

    async def open(self) -> None:
        await self.stack.__aenter__()

    async def close(self) -> None:
        try:
            await self.stack.__aexit__(None, None, None)
        except Exception:
            pass

    async def connect_server(self, key: str, spec: dict, on_status) -> ServerConn:
        """Connect one server. on_status(conn) is called as state changes."""
        conn = ServerConn(
            key=key,
            name=spec.get("name", key),
            category=spec.get("category", "generic"),
            color=tuple(spec.get("color", [255, 60, 60])),
            extractor=spec.get("extractor", ""),
            status="connecting",
        )
        self.conns[key] = conn
        on_status(conn)

        try:
            transport = spec.get("transport", "stdio")
            if transport == "stdio":
                session = await self._open_stdio(spec)
            else:
                raise RuntimeError(f"transport '{transport}' not enabled in this build")

            await session.initialize()
            conn.session = session

            listed = (await session.list_tools()).tools
            for t in listed:
                exposed = t.name
                if exposed in self.tool_route:  # collision -> namespace
                    exposed = f"{key}.{t.name}"
                info = ToolInfo(
                    name=exposed,
                    raw_name=t.name,
                    server_key=key,
                    description=t.description or "",
                    input_schema=_sanitise_schema(t.input_schema),
                )
                conn.tools.append(info)
                self.tool_route[exposed] = info

            conn.status = "online"
        except Exception as e:  # noqa: BLE001 - surface any startup failure
            conn.status = "error"
            conn.error = str(e).splitlines()[0][:200] if str(e) else e.__class__.__name__
        on_status(conn)
        return conn

    async def _open_stdio(self, spec: dict) -> ClientSession:
        env = dict(os.environ)
        env.update(spec.get("env", {}))
        cwd = spec.get("cwd") or self.base_dir
        params = StdioServerParameters(
            command=spec["command"],
            args=[str(a) for a in spec.get("args", [])],
            env=env,
            cwd=cwd,
        )
        read, write = await self.stack.enter_async_context(stdio_client(params))
        session = await self.stack.enter_async_context(ClientSession(read, write))
        return session

    # -- runtime ------------------------------------------------------------
    def bedrock_tool_config(self) -> dict:
        """Build a Bedrock Converse toolConfig from every online tool."""
        tools = []
        for info in self.tool_route.values():
            tools.append({"toolSpec": {
                "name": info.name,
                "description": info.description or info.name,
                "inputSchema": {"json": info.input_schema},
            }})
        return {"tools": tools} if tools else {"tools": []}

    def server_of(self, tool_name: str) -> str:
        info = self.tool_route.get(tool_name)
        return info.server_key if info else ""

    async def call(self, tool_name: str, args: dict) -> tuple[str, bool, Any]:
        """Call a tool. Returns (text, is_error, structured_content)."""
        info = self.tool_route.get(tool_name)
        if not info:
            return (f"unknown tool: {tool_name}", True, None)
        # approval gate: dangerous tools must be armed by an operator first
        if self.approvals is not None and not self.approvals.allowed(tool_name):
            return (f"BLOCKED: '{tool_name}' is a dangerous action and is not "
                    f"armed. An operator must arm it in the console before it "
                    f"can run.", True, None)
        # scope guardrail: block out-of-scope targets (inventory tools exempt)
        if self.scope is not None and info.raw_name not in SCOPE_EXEMPT_TOOLS:
            ok, bad = self.scope.check_args(args)
            if not ok:
                allowed = ", ".join(self.scope.entries()) or "(none)"
                return (f"BLOCKED: '{bad}' is outside the engagement scope. "
                        f"Authorised targets: {allowed}. Refusing to run "
                        f"{tool_name} against an out-of-scope target.", True, None)
        conn = self.conns.get(info.server_key)
        if not conn or conn.status != "online" or conn.session is None:
            return (f"server '{info.server_key}' offline", True, None)
        try:
            res = await conn.session.call_tool(info.raw_name, args)
        except Exception as e:  # noqa: BLE001
            return (f"tool error: {e}", True, None)
        text = "".join(
            c.text for c in res.content
            if getattr(c, "type", None) == "text" and getattr(c, "text", None)
        )
        return (text, bool(getattr(res, "is_error", False)),
                getattr(res, "structured_content", None))


def _sanitise_schema(schema: dict | None) -> dict:
    """Bedrock wants a plain JSON-Schema object. Strip pydantic 'title' noise
    but keep it a valid object schema."""
    if not schema or not isinstance(schema, dict):
        return {"type": "object", "properties": {}}
    out = dict(schema)
    out.pop("title", None)
    if out.get("type") != "object":
        out["type"] = "object"
    out.setdefault("properties", {})
    return out
