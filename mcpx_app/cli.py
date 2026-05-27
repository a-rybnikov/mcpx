"""CLI for mcpx."""

from __future__ import annotations

import asyncio
import json

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .banner import MCPX_BANNER
from .probe import probe_server

console = Console()


def _banner() -> None:
    console.print(f"[bold cyan]{MCPX_BANNER}[/bold cyan]")


class BannerGroup(click.Group):
    def get_help(self, ctx: click.Context) -> str:
        _banner()
        return super().get_help(ctx)


def _render_probe(data: dict) -> None:
    server = data.get("fingerprint", {})
    console.print(
        Panel(
            f"Transport:   {server.get('transport')}\n"
            f"Server:      {server.get('name')} {server.get('version')}\n"
            f"Capabilities: tools {'✓' if data.get('tools') else '✗'}  resources {'✓' if data.get('resources') else '✗'}  prompts {'✓' if data.get('prompts') else '✗'}",
            title=f"MCP Server: {data.get('endpoint') or data.get('url')}",
        )
    )
    table = Table(title=f"Tools ({len(data.get('tools', []))})")
    table.add_column("Name")
    table.add_column("Description")
    table.add_column("Flags")
    for tool in data.get("tools", []):
        flags = []
        name = str(tool.get("name", ""))
        if any(token in name.lower() for token in ("exec", "run", "shell", "eval")):
            flags.append("EXEC")
        if "schema" not in json.dumps(tool, ensure_ascii=False).lower():
            flags.append("NO_SCHEMA")
        table.add_row(name, str(tool.get("description", ""))[:80], " ".join(flags))
    console.print(table)
    findings = data.get("security_findings", [])
    if findings:
        console.print(f"[yellow]Security findings: {len(findings)}[/yellow]")
        for item in findings:
            console.print(f"  [{item['code']}] {item['message']}")


@click.group(cls=BannerGroup)
def main() -> None:
    """MAD MCP probe."""


@main.command("probe")
@click.argument("url")
@click.option("--json", "as_json", is_flag=True)
def probe_cmd(url: str, as_json: bool) -> None:
    """Run full probe."""
    data = asyncio.run(probe_server(url, save_json=as_json))
    if as_json:
        console.print_json(data=data)
    else:
        _render_probe(data)


@main.command("tools")
@click.argument("url")
def tools_cmd(url: str) -> None:
    data = asyncio.run(probe_server(url))
    table = Table(title="Tools")
    table.add_column("Name")
    table.add_column("Description")
    for tool in data.get("tools", []):
        table.add_row(str(tool.get("name", "")), str(tool.get("description", ""))[:100])
    console.print(table)


@main.command("resources")
@click.argument("url")
def resources_cmd(url: str) -> None:
    data = asyncio.run(probe_server(url))
    table = Table(title="Resources")
    table.add_column("URI")
    table.add_column("Name")
    for item in data.get("resources", []):
        table.add_row(str(item.get("uri", "")), str(item.get("name", "")))
    console.print(table)


@main.command("prompts")
@click.argument("url")
def prompts_cmd(url: str) -> None:
    data = asyncio.run(probe_server(url))
    table = Table(title="Prompts")
    table.add_column("Name")
    table.add_column("Description")
    for item in data.get("prompts", []):
        table.add_row(str(item.get("name", "")), str(item.get("description", ""))[:100])
    console.print(table)


@main.command("fingerprint")
@click.argument("url")
def fingerprint_cmd(url: str) -> None:
    data = asyncio.run(probe_server(url))
    console.print_json(data=data.get("fingerprint", {}))


@main.command("security")
@click.argument("url")
def security_cmd(url: str) -> None:
    data = asyncio.run(probe_server(url))
    table = Table(title="Security Findings")
    table.add_column("Code")
    table.add_column("Message")
    for item in data.get("security_findings", []):
        table.add_row(item["code"], item["message"])
    console.print(table)


if __name__ == "__main__":
    main()
