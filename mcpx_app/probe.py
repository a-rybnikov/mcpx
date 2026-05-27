"""Remote MCP probing."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from .store import write_artifact

DISCOVERY_PATHS = ("/sse", "/mcp", "/.well-known/mcp", "/")
EXEC_HINTS = ("run", "exec", "shell", "bash", "eval", "command")
FS_HINTS = ("file://", "/srv", "/home", "file:")
PROMPT_HINTS = ("ignore previous", "new instructions", "override", "system prompt")


@dataclass(slots=True)
class Endpoint:
    transport: str
    url: str


def _payload(method: str, params: dict[str, Any] | None = None, request_id: int = 1) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}


def _normalize_tool(item: dict[str, Any]) -> dict[str, Any]:
    if "name" in item:
        return item
    return item.get("tool", item)


async def discover_endpoint(url: str) -> Endpoint | None:
    base = url if url.startswith(("http://", "https://")) else f"https://{url}"
    async with httpx.AsyncClient(follow_redirects=True, timeout=15, headers={"Accept": "application/json, text/event-stream"}) as client:
        for path in DISCOVERY_PATHS:
            probe_url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            try:
                if path == "/mcp":
                    resp = await client.post(probe_url, json=_payload("initialize", {"protocolVersion": "2024-11-05", "clientInfo": {"name": "mcpx", "version": "0.1.0"}, "capabilities": {}}))
                else:
                    resp = await client.get(probe_url)
            except httpx.HTTPError:
                continue
            content_type = resp.headers.get("content-type", "")
            if "text/event-stream" in content_type or path == "/sse":
                return Endpoint("sse", probe_url)
            if resp.status_code < 500 and (path == "/mcp" or "json" in content_type or resp.text.strip().startswith("{")):
                return Endpoint("streamable-http", probe_url)
    return None


async def _mcp_call(client: httpx.AsyncClient, endpoint: Endpoint, method: str, params: dict[str, Any] | None = None, request_id: int = 1) -> dict[str, Any]:
    payload = _payload(method, params, request_id=request_id)
    if endpoint.transport == "sse":
        resp = await client.post(endpoint.url.replace("/sse", "/mcp") if endpoint.url.endswith("/sse") else endpoint.url, json=payload)
    else:
        resp = await client.post(endpoint.url, json=payload)
    if resp.status_code >= 400:
        return {"ok": False, "status_code": resp.status_code, "error": resp.text[:500]}
    try:
        return {"ok": True, "data": resp.json()}
    except json.JSONDecodeError:
        return {"ok": False, "status_code": resp.status_code, "error": resp.text[:500]}


def _extract_result(obj: dict[str, Any]) -> Any:
    return obj.get("data", {}).get("result", {})


def security_findings(server_info: dict[str, Any], tools: list[dict[str, Any]], resources: list[dict[str, Any]], prompts: list[dict[str, Any]], authless: bool) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if authless:
        findings.append({"code": "NO_AUTH", "message": "server answered without Authorization header"})
    info_dump = json.dumps(server_info, ensure_ascii=False).lower()
    if any(token in info_dump for token in FS_HINTS):
        findings.append({"code": "INFO_DISCLOSURE", "message": "serverInfo leaks internal paths or names"})
    for tool in tools:
        name = str(tool.get("name", ""))
        schema = tool.get("inputSchema") or tool.get("input_schema")
        if not schema:
            findings.append({"code": "TOOL_NO_SCHEMA", "message": f"{name} has no input schema"})
        if any(hint in name.lower() for hint in EXEC_HINTS):
            findings.append({"code": "TOOL_EXEC_HINT", "message": f"{name} suggests command execution"})
    for resource in resources:
        uri = str(resource.get("uri") or resource.get("name") or "")
        if any(hint in uri for hint in FS_HINTS):
            findings.append({"code": "RESOURCE_FS_HINT", "message": f"{uri} exposes filesystem-like access"})
        if "*" in uri or "{" in uri:
            findings.append({"code": "WILDCARD_RESOURCES", "message": f"{uri} appears wildcarded"})
    for prompt in prompts:
        content = json.dumps(prompt, ensure_ascii=False).lower()
        if any(hint in content for hint in PROMPT_HINTS):
            findings.append({"code": "PROMPT_INJECTION_HINT", "message": f"{prompt.get('name', 'prompt')} contains instruction-override phrasing"})
    return findings


def fingerprint(server_info: dict[str, Any], capabilities: dict[str, Any], endpoint: Endpoint | None) -> dict[str, str]:
    name = str(server_info.get("name", "unknown"))
    version = str(server_info.get("version", "unknown"))
    flavor = "unknown"
    haystack = (name + " " + version + " " + json.dumps(capabilities, ensure_ascii=False)).lower()
    if "fastmcp" in haystack:
        flavor = "fastmcp"
    elif "cloudflare" in haystack:
        flavor = "cloudflare"
    elif "smithery" in haystack:
        flavor = "smithery"
    elif "mcp" in haystack:
        flavor = "generic-mcp"
    return {"name": name, "version": version, "flavor": flavor, "transport": endpoint.transport if endpoint else "unknown"}


async def probe_server(url: str, *, save_json: bool = False) -> dict[str, Any]:
    endpoint = await discover_endpoint(url)
    result: dict[str, Any] = {
        "url": url,
        "mcp_detected": False,
        "transport": endpoint.transport if endpoint else None,
        "endpoint": endpoint.url if endpoint else None,
        "serverInfo": {},
        "capabilities": {},
        "tools": [],
        "resources": [],
        "prompts": [],
        "security_findings": [],
    }
    if endpoint is None:
        if save_json:
            result["artifact_path"] = str(write_artifact(url, result))
        return result

    async with httpx.AsyncClient(follow_redirects=True, timeout=20) as client:
        initialize = await _mcp_call(client, endpoint, "initialize", {"protocolVersion": "2024-11-05", "clientInfo": {"name": "mcpx", "version": "0.1.0"}, "capabilities": {}})
        init_result = _extract_result(initialize) if initialize.get("ok") else {}
        result["serverInfo"] = init_result.get("serverInfo", {})
        result["capabilities"] = init_result.get("capabilities", {})

        tools_obj = await _mcp_call(client, endpoint, "tools/list", request_id=2)
        resources_obj = await _mcp_call(client, endpoint, "resources/list", request_id=3)
        prompts_obj = await _mcp_call(client, endpoint, "prompts/list", request_id=4)

        result["tools"] = [_normalize_tool(item) for item in (_extract_result(tools_obj).get("tools", []) if tools_obj.get("ok") else [])]
        result["resources"] = _extract_result(resources_obj).get("resources", []) if resources_obj.get("ok") else []
        result["prompts"] = _extract_result(prompts_obj).get("prompts", []) if prompts_obj.get("ok") else []
        result["mcp_detected"] = bool(result["serverInfo"] or result["capabilities"] or result["tools"] or result["resources"] or result["prompts"])
        result["fingerprint"] = fingerprint(result["serverInfo"], result["capabilities"], endpoint)
        result["security_findings"] = (
            security_findings(result["serverInfo"], result["tools"], result["resources"], result["prompts"], authless=True)
            if result["mcp_detected"]
            else []
        )

    if save_json:
        result["artifact_path"] = str(write_artifact(url, result))
    return result
