"""Background worker event loop.

Owns the asyncio loop, the MCP manager, the Bedrock client and the agent.
Consumes commands from the bridge one at a time and emits events back.
"""
from __future__ import annotations

import asyncio

from .bedrock import BedrockLLM
from .bridge import (BatchEnd, BatchProgress, BatchRun, BatchStart,
                     CallToolDirect, Connected, Connect, Error,
                     ListModels, ModelsList, ServerStatus, ServerTools, Shutdown,
                     Status, ToolEnd, ToolStart, UserMessage)
from .mcp_manager import MCPManager


async def worker_main(bridge, config: dict) -> None:
    loop = asyncio.get_running_loop()
    servers_cfg = config.get("servers", {})
    base_dir = config.get("_base_dir", ".")

    mgr = MCPManager(servers_cfg, base_dir, scope=config.get("scope"),
                     approvals=config.get("approvals"))
    await mgr.open()

    llm: BedrockLLM | None = None
    agent = None
    servers_connected = False

    def status_cb(conn):
        bridge.emit(ServerStatus(conn.key, conn.name, conn.category,
                                 conn.status, conn.color, conn.error))
        if conn.status == "online":
            bridge.emit(ServerTools(conn.key, [t.name for t in conn.tools]))

    async def connect_servers():
        nonlocal servers_connected
        if servers_connected:
            return
        servers_connected = True
        for key, spec in servers_cfg.items():
            if not spec.get("enabled", True):
                continue
            await mgr.connect_server(key, spec, status_cb)

    try:
        while True:
            cmd = await loop.run_in_executor(None, bridge.cmds.get)

            if isinstance(cmd, Shutdown):
                break

            elif isinstance(cmd, ListModels):
                try:
                    probe = BedrockLLM(cmd.profile, cmd.region)
                    models = await loop.run_in_executor(None, probe.list_models)
                    bridge.emit(ModelsList(models))
                except Exception as e:  # noqa: BLE001
                    bridge.emit(ModelsList([], error=str(e)))

            elif isinstance(cmd, Connect):
                try:
                    llm = BedrockLLM(cmd.profile, cmd.region)
                    from .agent import Agent
                    agent = Agent(llm, mgr, bridge, cmd.model_id)
                    bridge.emit(Connected(cmd.model_id, cmd.model_label))
                    bridge.emit(Status("LINK ESTABLISHED"))
                    await connect_servers()
                except Exception as e:  # noqa: BLE001
                    bridge.emit(Error(f"connect failed: {e}", fatal=False))

            elif isinstance(cmd, UserMessage):
                if agent is None:
                    bridge.emit(Error("no active link"))
                else:
                    try:
                        await agent.run_turn(cmd.text)
                    except Exception as e:  # noqa: BLE001
                        bridge.emit(Error(f"turn failed: {e}"))

            elif isinstance(cmd, CallToolDirect):
                server = mgr.server_of(cmd.tool)
                bridge.emit(ToolStart(cmd.tool, server, cmd.args))
                text, is_error, structured = await mgr.call(cmd.tool, cmd.args)
                bridge.emit(ToolEnd(cmd.tool, server, text, is_error))
                if not is_error and agent is not None:
                    agent._emit_hosts(cmd.tool, text, structured)

            elif isinstance(cmd, BatchRun):
                steps = cmd.steps or []
                total = len(cmd.targets) * max(1, len(steps))
                names = ",".join(s.get("tool", "") for s in steps)
                bridge.emit(BatchStart(names, total, cmd.label))
                okc = failc = idx = 0
                for ep in cmd.targets:
                    for st in steps:
                        idx += 1
                        tool = st.get("tool", "")
                        args = dict(st.get("args", {}))
                        args[st.get("target_key", "target")] = ep.get("target", "")
                        server = mgr.server_of(tool)
                        bridge.emit(ToolStart(tool, server, args))
                        text, is_error, structured = await mgr.call(tool, args)
                        bridge.emit(ToolEnd(tool, server, text, is_error))
                        if not is_error and agent is not None:
                            agent._emit_hosts(tool, text, structured)
                        okc += 0 if is_error else 1
                        failc += 1 if is_error else 0
                        label = f"{ep.get('target', '')} [{tool}]"
                        bridge.emit(BatchProgress(idx, total, label,
                                                  not is_error, (text or "")[:160]))
                bridge.emit(BatchEnd(names, total, okc, failc, cmd.label))
    finally:
        await mgr.close()
