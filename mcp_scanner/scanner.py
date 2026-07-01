"""Scanner engine for MCP server configs and source files."""

from __future__ import annotations
import time
from pathlib import Path

from mcp_scanner.models import ScanResult, Finding, Severity
from mcp_scanner.parser import parse_config
from mcp_scanner.rules.checks import (
    check_dangerous_command,
    check_env_secrets,
    check_unrestricted_access,
    check_package_verification,
    check_argument_injection,
)


def scan_config(config_path: str) -> ScanResult:
    """Scan an MCP server configuration file for security issues."""
    start = time.time()
    config = parse_config(config_path)
    findings: list[Finding] = []

    for name, spec in config.servers.items():
        findings.extend(check_dangerous_command(name, spec.command, spec.args, config.source_file))
        findings.extend(check_env_secrets(name, spec.env, config.source_file))
        findings.extend(check_unrestricted_access(name, spec.args, config.source_file))
        findings.extend(check_package_verification(name, spec.command, spec.args, config.source_file))
        findings.extend(check_argument_injection(name, spec.command, spec.args, config.source_file))

    # Also scan referenced source files
    files_scanned = 0
    if config_path and Path(config_path).exists():
        files_scanned = 1  # the config file
    for name, spec in config.servers.items():
        from mcp_scanner.parser import scan_mcp_source
        source_files = scan_mcp_source(name, spec)
        files_scanned += len(source_files)

    duration = int((time.time() - start) * 1000)

    return ScanResult(
        target=config_path,
        files_scanned=files_scanned,
        findings=findings,
        scan_duration_ms=duration,
    )


def scan_source_file(file_path: str) -> list[Finding]:
    """Scan an MCP server source file for security issues."""
    findings: list[Finding] = []
    path = Path(file_path)

    if not path.exists():
        return findings

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    # Import AgentGuard rules for deep scanning
    try:
        from agentguard.scanner import scan_file as ag_scan
        ag_findings = ag_scan(path)
        findings.extend(ag_findings)
    except ImportError:
        # AgentGuard not installed — do basic checks
        import re
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if re.search(r'\beval\s*\(', stripped):
                findings.append(Finding(
                    rule_id="MCP-EVAL",
                    rule_name="eval() in MCP server",
                    severity=Severity.CRITICAL,
                    file=str(path),
                    line=i,
                    snippet=stripped[:200],
                    description="eval() in MCP server source — code execution vulnerability",
                    recommendation="Remove eval(). Use safe alternatives.",
                    confidence=0.95,
                ))

    return findings
