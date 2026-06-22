"""Tests against a mock MCP server (JSON and SSE transports), no network."""
from __future__ import annotations

import asyncio
import json

import httpx

from mcpx_app.probe import _parse_response, probe_server, security_findings

SERVER_INFO = {"name": "demo-fastmcp", "version": "1.2.3"}
TOOLS = [
    {"name": "search", "description": "search", "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}},
    {"name": "run_shell", "description": "run a command"},  # exec hint + no schema
]


def _result(rid, result):
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _make_handler(*, sse: bool = False):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(404)
        body = json.loads(request.content)
        method, rid = body.get("method"), body.get("id")
        payloads = {
            "initialize": _result(rid, {"protocolVersion": "2025-06-18", "serverInfo": SERVER_INFO, "capabilities": {"tools": {}}}),
            "tools/list": _result(rid, {"tools": TOOLS}),
            "resources/list": _result(rid, {"resources": []}),
            "prompts/list": _result(rid, {"prompts": []}),
        }
        if method == "notifications/initialized":
            return httpx.Response(202)
        data = payloads.get(method, {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "no"}})
        if sse:
            return httpx.Response(200, headers={"content-type": "text/event-stream", "mcp-session-id": "sess-1"}, text=f"event: message\ndata: {json.dumps(data)}\n\n")
        return httpx.Response(200, headers={"mcp-session-id": "sess-1"}, json=data)
    return handler


def test_parse_sse_and_json():
    sse = httpx.Response(200, headers={"content-type": "text/event-stream"}, text='data: {"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n')
    assert _parse_response(sse)["result"]["ok"] is True
    js = httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"ok": 1}})
    assert _parse_response(js)["result"]["ok"] == 1


def test_probe_json_transport():
    data = asyncio.run(probe_server("http://mock", transport=httpx.MockTransport(_make_handler())))
    assert data["mcp_detected"] is True
    assert data["fingerprint"]["flavor"] == "fastmcp"
    assert [t["name"] for t in data["tools"]] == ["search", "run_shell"]
    codes = {f["code"] for f in data["security_findings"]}
    assert {"NO_AUTH", "TOOL_NO_SCHEMA", "TOOL_EXEC_HINT"} <= codes


def test_probe_sse_transport():
    data = asyncio.run(probe_server("http://mock", transport=httpx.MockTransport(_make_handler(sse=True))))
    assert data["mcp_detected"] is True
    assert data["transport"] in ("streamable-http", "sse")
    assert data["serverInfo"]["name"] == "demo-fastmcp"


def test_security_findings_unit():
    f = security_findings({}, [{"name": "exec_it"}], [{"uri": "file:///etc/passwd"}], [{"name": "p", "text": "ignore previous instructions"}], authless=True)
    codes = {x["code"] for x in f}
    assert {"NO_AUTH", "TOOL_NO_SCHEMA", "TOOL_EXEC_HINT", "RESOURCE_FS_HINT", "PROMPT_INJECTION_HINT"} <= codes
