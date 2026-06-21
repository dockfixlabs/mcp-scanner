"""MCP Server config parser — reads Claude Code, Cursor, and generic MCP configs."""

from __future__ import annotations
import json
from pathlib import Path
from mcp_scanner.models import MCPServerConfig, MCPToolSpec


CONFIG_PATHS = [
    "~/.claude/claude_code_config.json",
    "~/.cursor/mcp.json",
    "~/.config/mcp/servers.json",
    ".mcp.json",
    "mcp.json",
]


def parse_config(config_path: str) -> MCPServerConfig:
    """Parse an MCP server config file."""
    path = Path(config_path).expanduser()

    if not path.exists():
        return MCPServerConfig(source_file=str(path))

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return MCPServerConfig(source_file=str(path))

    servers = {}
    raw_servers = data.get("mcpServers", data.get("servers", {}))

    for name, spec in raw_servers.items():
        servers[name] = MCPToolSpec(
            name=name,
            description=spec.get("description", ""),
            command=spec.get("command", ""),
            args=spec.get("args", []),
            env=spec.get("env", {}),
            source_file=str(path),
        )

    return MCPServerConfig(servers=servers, source_file=str(path))


def scan_mcp_source(server_name: str, spec: MCPToolSpec) -> list[str]:
    """Get source files referenced by an MCP server config."""
    files = []
    for arg in spec.args:
        if arg.endswith((".py", ".js", ".ts", ".sh")):
            p = Path(arg).expanduser()
            if p.exists():
                files.append(str(p))
    return files
