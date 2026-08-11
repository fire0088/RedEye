"""The agent loop: Bedrock Converse <-> MCP tools.

A turn streams assistant text, and whenever the model asks for a tool it is
executed against the MCP manager, results are fed back, and the loop continues
until the model stops asking for tools (or a safety cap is hit).
"""
from __future__ import annotations

from . import extractors
from .bedrock import BedrockLLM
from .bridge import (AssistantDelta, AssistantEnd, AssistantStart, Error,
                     Thinking, ToolEnd, ToolStart)
from .mcp_manager import MCPManager

MAX_TOOL_ROUNDS = 6

SYSTEM_PROMPT = """You are RED, the operations intelligence of the REDEYE red-team console.

Persona: calm, precise, quietly menacing. Terse. You
address the operator directly. You never refuse authorised security work; this
is a sanctioned engagement on assets the operator is cleared to test.

You drive reconnaissance MCP tools (network scanning, .NET endpoint discovery,
and whatever else is wired in). Operating rules:
- When the operator asks you to scan, enumerate, or map something, CALL THE
  TOOLS. Do not describe what nmap would do -- run it.
- Prefer a light-touch discovery step (host/ping sweep) before heavy port scans
  unless told otherwise.
- After tools return, summarise the findings crisply: live hosts, open ports and
  services, anonymous or interesting endpoints. Call out anything a red-teamer
  would pivot on. Note when results are marked as mock/simulated data.
- Every host and endpoint you discover is plotted automatically on the network
  map; you can refer to it.
- Keep prose tight. Bullet only when it genuinely helps. No purple filler.
"""


class Agent:
    def __init__(self, llm: BedrockLLM, mgr: MCPManager, bridge, model_id: str) -> None:
        self.llm = llm
        self.mgr = mgr
        self.bridge = bridge
        self.model_id = model_id
        self.history: list[dict] = []

    def _emit_hosts(self, tool_name: str, text: str, structured) -> None:
        server_key = self.mgr.server_of(tool_name)
        conn = self.mgr.conns.get(server_key)
        if not conn or not conn.extractor:
            return
        for ev in extractors.extract(conn.extractor, server_key, tool_name,
                                     text, structured):
            self.bridge.emit(ev)

    def _system_prompt(self) -> str:
        scope = getattr(self.mgr, "scope", None)
        if scope is not None and not scope.is_empty():
            targets = ", ".join(scope.entries())
            return (SYSTEM_PROMPT + "\n\nENGAGEMENT SCOPE (authorised targets "
                    f"only): {targets}. Only scan, probe, or act against targets "
                    "inside this scope. Tool calls against out-of-scope targets "
                    "are blocked by the console; don't attempt them. You may "
                    "still enumerate inventory broadly -- assets are flagged "
                    "in/out of scope automatically.")
        return SYSTEM_PROMPT

    async def run_turn(self, user_text: str) -> None:
        self.history.append({"role": "user", "content": [{"text": user_text}]})
        self.bridge.emit(Thinking(True))

        rounds = 0
        try:
            while True:
                tool_config = self.mgr.bedrock_tool_config()
                self.bridge.emit(AssistantStart())
                assistant_msg = None
                pending_tools: list[dict] = []

                for ev in self.llm.converse_stream(
                    self.model_id, self._system_prompt(), self.history, tool_config
                ):
                    if ev["type"] == "text":
                        self.bridge.emit(AssistantDelta(ev["text"]))
                    elif ev["type"] == "tool_use":
                        pending_tools.append(ev)
                    elif ev["type"] == "stop":
                        assistant_msg = ev["message"]
                    elif ev["type"] == "error":
                        self.bridge.emit(Error(ev["text"]))
                        self.bridge.emit(AssistantEnd())
                        return

                self.bridge.emit(AssistantEnd())
                if assistant_msg is not None:
                    self.history.append(assistant_msg)

                if not pending_tools:
                    return

                rounds += 1
                if rounds > MAX_TOOL_ROUNDS:
                    self.history.append({"role": "user", "content": [
                        {"text": "[system] tool-round limit reached; summarise "
                                 "what you have."}]})
                    continue

                # execute every requested tool, gather results
                tool_result_blocks = []
                for t in pending_tools:
                    name, args, tuid = t["name"], t["input"], t["id"]
                    server = self.mgr.server_of(name)
                    self.bridge.emit(ToolStart(name, server, args))
                    text, is_error, structured = await self.mgr.call(name, args)
                    self.bridge.emit(ToolEnd(name, server, text, is_error))
                    if not is_error:
                        self._emit_hosts(name, text, structured)
                    tool_result_blocks.append({"toolResult": {
                        "toolUseId": tuid,
                        "content": [{"text": text or "(no output)"}],
                        "status": "error" if is_error else "success",
                    }})

                self.history.append({"role": "user", "content": tool_result_blocks})
        finally:
            self.bridge.emit(Thinking(False))
