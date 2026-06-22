# mcpx

**Black-box reconnaissance for Model Context Protocol (MCP) servers.**

> *Speak softly · carry a big list.*

Point `mcpx` at a remote MCP endpoint and it discovers the transport, completes
the JSON-RPC handshake, enumerates every **tool / resource / prompt**,
fingerprints the implementation, and flags posture issues — all read-only.

It is the recon step of an MCP assessment; once you know the surface,
[**needler**](https://github.com/a-rybnikov/needler) fuzzes the tools and
[**overreach**](https://github.com/a-rybnikov/overreach) grades their agency.
Lineage: [garak](https://github.com/NVIDIA/garak) / [PyRIT](https://github.com/Azure/PyRIT).

---

## What it does

- **Transport discovery** — probes `/mcp`, `/sse`, `/.well-known/mcp`, `/`;
  detects streamable-HTTP vs SSE.
- **Real handshake** — JSON-RPC 2.0 `initialize` (protocol `2025-06-18`) +
  `notifications/initialized`, carrying the `Mcp-Session-Id` the server issues,
  and parsing **both** JSON and `text/event-stream` replies.
- **Enumeration** — `tools/list`, `resources/list`, `prompts/list`.
- **Fingerprint** — name / version / flavor (fastmcp, cloudflare, smithery…).
- **Posture findings** — `NO_AUTH` (answered without an Authorization header),
  `TOOL_NO_SCHEMA`, `TOOL_EXEC_HINT`, `RESOURCE_FS_HINT`, `WILDCARD_RESOURCE`,
  `PROMPT_INJECTION_HINT`, `INFO_DISCLOSURE`.

## Use

```bash
pip install -e .

mcpx probe https://target/mcp          # full report
mcpx probe https://target/mcp --json   # machine-readable artifact
mcpx tools https://target/mcp          # just the tool inventory
mcpx security https://target/mcp       # just the findings
mcpx fingerprint https://target/mcp
```

## Tests

```bash
pip install -e ".[test]" && pytest
```

Covers discovery + handshake + enumeration against a mock MCP server over both
JSON and SSE transports, and the posture-finding logic — no network.

## Responsible use

Probe only MCP servers you own or are authorised to assess. `mcpx` is
read-only: it lists and fingerprints, it does not call tools.

---

Part of the **MAD** toolkit — small, sharp instruments for the security of
autonomous-agent systems.
