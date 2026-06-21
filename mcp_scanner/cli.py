"""CLI for MCP Scanner."""

from __future__ import annotations
import sys
import json
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mcp_scanner.scanner import scan_config


@click.command()
@click.argument("config_path", default="~/.claude/claude_code_config.json")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text")
@click.option("--exit-code/--no-exit-code", default=True)
def main(config_path: str, fmt: str, exit_code: bool) -> None:
    """MCP Scanner — Security scanner for MCP server configurations.

    CONFIG_PATH: Path to MCP config file (default: ~/.claude/claude_code_config.json)

    Examples:
        mcp-scanner                          # Scan default Claude Code config
        mcp-scanner .mcp.json                # Scan project-level MCP config
        mcp-scanner ~/.cursor/mcp.json       # Scan Cursor config
    """
    console = Console()
    result = scan_config(config_path)

    if fmt == "json":
        print(json.dumps(result.model_dump(), indent=2, default=str))
    else:
        console.print()
        console.print(Panel.fit(
            f"[bold cyan]MCP Scanner[/bold cyan] — MCP Server Security Scan\n"
            f"Config: [white]{result.target}[/white]\n"
            f"Servers found: [white]{result.files_scanned - 1}[/white]",
            border_style="cyan",
        ))

        if result.clean:
            console.print("[bold green]✓ No vulnerabilities found.[/bold green]")
        else:
            table = Table(show_header=True, header_style="bold", border_style="dim")
            table.add_column("Severity", width=12)
            table.add_column("Rule", width=25)
            table.add_column("Description")

            for f in result.findings:
                sev_color = {
                    "CRITICAL": "bold red", "HIGH": "red",
                    "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim",
                }.get(f.severity.value, "white")
                table.add_row(
                    f"[{sev_color}]{f.severity.value}[/{sev_color}]",
                    f.rule_name,
                    f.description,
                )
            console.print(table)
            console.print()

            console.print("[bold]Recommendations:[/bold]")
            for f in result.findings:
                console.print(f"  • {f.rule_name}: {f.recommendation}")

        console.print()

    if exit_code and not result.clean:
        sys.exit(1)


if __name__ == "__main__":
    main()
