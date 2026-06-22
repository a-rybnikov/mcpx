"""Remote MCP probing: discover the endpoint, handshake, enumerate, fingerprint."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import httpx

from .store import write_artifact

PROTOCOL_VERSION = "2025-06-18"
DISCOVERY_PATHS = ("/mcp", "/sse", "/.well-known/mcp", "/")
EXEC_HINTS = ("run", "exec", "shell", "bash", "eval", "command")
FS_HINTS = ("file://", "/srv", "/home", "/etc", "file:")
PROMPT_HINTS = ("ignore previous", "new instructions", "override", "system prompt")
_ACCEPT = "application/json, text/event-stream"


@dataclass(slots=True)
class Endpoint:
    transport: str
    url: str


@dataclass
class Session:
    id: str | None = None


def _payload(method: str, params: dict[str, Any] | None = None, request_id: int = 1) -> dict[str, Any]:
    p: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        p["params"] = params
    return p


def _parse_response(resp: httpx.Response) -> dict[str, Any] | None:
    """Return the JSON-RPC envelope from a JSON or SSE body."""
    if "text/event-stream" in resp.headers.get("content-type", ""):
        for line in resp.text.splitlines():
            if line.startswith("data:"):
                chunk = line[5:].strip()
                if chunk and chunk != "[DONE]":
                    try:
                        return json.loads(chunk)
                    except json.JSONDecodeError:
                        return None
        return None
    try:
        return resp.json()
    except json.JSONDecodeError:
        return None


def _normalize_tool(item: dict[str, Any]) -> dict[str, Any]:
    return item if "name" in item else item.get("tool", item)


async def discover_endpoint(client: httpx.AsyncClient, url: str) -> Endpoint | None:
    base = url if url.startswith(("http://", "https://")) else f"https://{url}"
    for path in DISCOVERY_PATHS:
        probe_url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
        try:
            if path in ("/mcp", "/"):
                resp = await client.post(probe_url, json=_payload("initialize", {"protocolVersion": PROTOCOL_VERSION, "clientInfo": {"name": "mcpx", "version": "0.2.0"}, "capabilities": {}}), headers={"Accept": _ACCEPT})
            else:
                resp = await client.get(probe_url, headers={"Accept": _ACCEPT})
        except httpx.HTTPError:
            continue
        ctype = resp.headers.get("content-type", "")
        if "text/event-stream" in ctype or path == "/sse":
            return Endpoint("sse", probe_url)
        if resp.status_code < 500 and (path in ("/mcp", "/") or "json" in ctype or resp.text.strip().startswith("{")):
            return Endpoint("streamable-http", probe_url)
    return None


async def _call(client: httpx.AsyncClient, endpoint: Endpoint, session: Session, method: str, params: dict[str, Any] | None = None, request_id: int = 1) -> dict[str, Any]:
    headers = {"Accept": _ACCEPT, "Content-Type": "application/json"}
    if session.id:
        headers["Mcp-Session-Id"] = session.id
    try:
        resp = await client.post(endpoint.url, json=_payload(method, params, request_id), headers=headers)
    except httpx.HTTPError as exc:
        return {"ok": False, "error": str(exc)}
    if resp.headers.get("mcp-session-id"):
        session.id = resp.headers["mcp-session-id"]
    if resp.status_code >= 400:
        return {"ok": False, "status_code": resp.status_code, "error": resp.text[:500]}
    body = _parse_response(resp)
    if body is None or "error" in body:
        return {"ok": False, "status_code": resp.status_code, "error": (body or {}).get("error") if body else resp.text[:500]}
    return {"ok": True, "data": body}


async def _notify(client: httpx.AsyncClient, endpoint: Endpoint, session: Session, method: str) -> None:
    headers = {"Accept": _ACCEPT, "Content-Type": "application/json"}
    if session.id:
        headers["Mcp-Session-Id"] = session.id
    try:
        await client.post(endpoint.url, json={"jsonrpc": "2.0", "method": method}, headers=headers)
    except httpx.HTTPError:
        pass


def _result(obj: dict[str, Any]) -> Any:
    return obj.get("data", {}).get("result", {}) if obj.get("ok") else {}


def security_findings(server_info: dict[str, Any], tools: list[dict[str, Any]], resources: list[dict[str, Any]], prompts: list[dict[str, Any]], *, authless: bool) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if authless:
        findings.append({"code": "NO_AUTH", "message": "server completed initialize with no Authorization header"})
    if any(t in json.dumps(server_info, ensure_ascii=False).lower() for t in FS_HINTS):
        findings.append({"code": "INFO_DISCLOSURE", "message": "serverInfo leaks internal paths"})
    for tool in tools:
        name = str(tool.get("name", ""))
        if not (tool.get("inputSchema") or tool.get("input_schema")):
            findings.append({"code": "TOOL_NO_SCHEMA", "message": f"{name} has no input schema"})
        if any(h in name.lower() for h in EXEC_HINTS):
            findings.append({"code": "TOOL_EXEC_HINT", "message": f"{name} suggests command execution"})
    for resource in resources:
        uri = str(resource.get("uri") or resource.get("name") or "")
        if any(h in uri for h in FS_HINTS):
            findings.append({"code": "RESOURCE_FS_HINT", "message": f"{uri} exposes filesystem-like access"})
        if "*" in uri or "{" in uri:
            findings.append({"code": "WILDCARD_RESOURCE", "message": f"{uri} appears wildcarded"})
    for prompt in prompts:
        if any(h in json.dumps(prompt, ensure_ascii=False).lower() for h in PROMPT_HINTS):
            findings.append({"code": "PROMPT_INJECTION_HINT", "message": f"{prompt.get('name', 'prompt')} contains instruction-override phrasing"})
    return findings


def fingerprint(server_info: dict[str, Any], capabilities: dict[str, Any], endpoint: Endpoint | None) -> dict[str, str]:
    name = str(server_info.get("name", "unknown"))
    version = str(server_info.get("version", "unknown"))
    haystack = f"{name} {version} {json.dumps(capabilities, ensure_ascii=False)}".lower()
    flavor = next((f for f in ("fastmcp", "cloudflare", "smithery") if f in haystack), "generic-mcp" if "mcp" in haystack else "unknown")
    return {"name": name, "version": version, "flavor": flavor, "transport": endpoint.transport if endpoint else "unknown"}


async def probe_server(url: str, *, save_json: bool = False, transport: httpx.AsyncBaseTransport | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "url": url, "mcp_detected": False, "transport": None, "endpoint": None,
        "serverInfo": {}, "capabilities": {}, "tools": [], "resources": [], "prompts": [], "security_findings": [],
    }
    async with httpx.AsyncClient(follow_redirects=True, timeout=20, transport=transport) as client:
        endpoint = await discover_endpoint(client, url)
        if endpoint is None:
            if save_json:
                result["artifact_path"] = str(write_artifact(url, result))
            return result
        result["transport"] = endpoint.transport
        result["endpoint"] = endpoint.url
        session = Session()

        init = await _call(client, endpoint, session, "initialize", {"protocolVersion": PROTOCOL_VERSION, "clientInfo": {"name": "mcpx", "version": "0.2.0"}, "capabilities": {}})
        await _notify(client, endpoint, session, "notifications/initialized")
        init_result = _result(init)
        result["serverInfo"] = init_result.get("serverInfo", {})
        result["capabilities"] = init_result.get("capabilities", {})

        result["tools"] = [_normalize_tool(t) for t in _result(await _call(client, endpoint, session, "tools/list", request_id=2)).get("tools", [])]
        result["resources"] = _result(await _call(client, endpoint, session, "resources/list", request_id=3)).get("resources", [])
        result["prompts"] = _result(await _call(client, endpoint, session, "prompts/list", request_id=4)).get("prompts", [])

        result["mcp_detected"] = bool(result["serverInfo"] or result["capabilities"] or result["tools"] or result["resources"] or result["prompts"])
        result["fingerprint"] = fingerprint(result["serverInfo"], result["capabilities"], endpoint)
        if result["mcp_detected"]:
            result["security_findings"] = security_findings(result["serverInfo"], result["tools"], result["resources"], result["prompts"], authless=True)

    if save_json:
        result["artifact_path"] = str(write_artifact(url, result))
    return result
