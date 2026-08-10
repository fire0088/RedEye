#!/usr/bin/env python3
"""ASP.NET endpoint-discovery MCP server for REDEYE.

Wraps the local Roslyn-based endpoint extractor (the one from the reachnet
pipeline: routes + HTTP verb + auth classification + handler symbol, including
minimal-API entry points). This server is a thin, swappable adapter: point it at
your extractor and it forwards the JSON; without it, it emits clearly-flagged
mock endpoints so the map still populates.

Environment:
    REDEYE_ROSLYN_CMD    command template for the extractor, e.g.
                         "dotnet /opt/reachnet/EndpointExtractor.dll --json {project}"
                         or "reachnet endpoints --json {project}".
                         {project} is substituted with the project path.
                         The command MUST print endpoint JSON to stdout.

Expected extractor JSON (either shape is accepted):
    {"app": "...", "base_url": "...", "endpoints": [
        {"route": "/api/x", "verb": "GET", "auth": "anonymous",
         "handler": "Ns.Controller::Method/1"}, ...]}
  or {"apps": [ {..as above..}, ... ]}

Tools:
    discover_endpoints(project_path)
    list_anonymous(project_path)     # convenience filter
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess

from mcp.server import MCPServer

srv = MCPServer("redeye-roslyn-endpoints")

CMD_TEMPLATE = os.environ.get("REDEYE_ROSLYN_CMD", "").strip()


def _run_extractor(project_path: str) -> dict:
    cmd = CMD_TEMPLATE.replace("{project}", shlex.quote(project_path))
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          timeout=600)
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(proc.stderr.strip() or f"extractor exited {proc.returncode}")
    data = json.loads(proc.stdout)
    data["mock"] = False
    return _normalise(data, project_path)


def _normalise(data: dict, project_path: str) -> dict:
    if "apps" in data:
        return data
    app = data.get("app") or os.path.basename(project_path.rstrip("/\\")) or "webapp"
    return {"apps": [{
        "app": app,
        "base_url": data.get("base_url", ""),
        "endpoints": data.get("endpoints", []),
    }], "mock": data.get("mock", False)}


def _mock(project_path: str) -> dict:
    app = os.path.basename(project_path.rstrip("/\\")) or "OrdersApi"
    endpoints = [
        {"route": "/health", "verb": "GET", "auth": "anonymous",
         "handler": "OrdersApi.HealthController::Get/0"},
        {"route": "/api/auth/login", "verb": "POST", "auth": "anonymous",
         "handler": "OrdersApi.AuthController::Login/1"},
        {"route": "/api/orders", "verb": "GET", "auth": "authenticated",
         "handler": "OrdersApi.OrdersController::List/0"},
        {"route": "/api/orders/{id}", "verb": "GET", "auth": "authenticated",
         "handler": "OrdersApi.OrdersController::GetById/1"},
        {"route": "/api/orders/{id}", "verb": "DELETE", "auth": "authorize:Admin",
         "handler": "OrdersApi.OrdersController::Delete/1"},
        {"route": "/internal/debug/dump", "verb": "GET", "auth": "anonymous",
         "handler": "OrdersApi.DebugEndpoints::Dump/0"},
        {"route": "/api/export", "verb": "GET", "auth": "unknown",
         "handler": "OrdersApi.ExportController::Export/0"},
    ]
    return {"apps": [{"app": app, "base_url": "https://orders.internal.lab",
                      "endpoints": endpoints}], "mock": True}


@srv.tool(description="Discover ASP.NET HTTP endpoints in a .NET project via the "
                      "Roslyn extractor. Returns JSON: apps[].endpoints[] with "
                      "route, verb, auth classification, and handler symbol. "
                      "Endpoints are plotted on the network map, coloured by auth "
                      "posture (anonymous endpoints flagged red).")
def discover_endpoints(project_path: str) -> str:
    if not CMD_TEMPLATE:
        return json.dumps(_mock(project_path))
    try:
        return json.dumps(_run_extractor(project_path))
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": str(e), "project": project_path,
                           "mock": False, "apps": []})


@srv.tool(description="Discover endpoints and return only the anonymous / "
                      "unauthenticated ones -- the endpoints most worth probing "
                      "first. Same JSON shape as discover_endpoints.")
def list_anonymous(project_path: str) -> str:
    raw = json.loads(discover_endpoints(project_path))
    for app in raw.get("apps", []):
        app["endpoints"] = [
            e for e in app.get("endpoints", [])
            if e.get("auth", "").startswith(("anon", "allow_anon", "none"))
        ]
    return json.dumps(raw)


if __name__ == "__main__":
    srv.run("stdio")
