"""MCP-specific security rules."""

from __future__ import annotations
import re
from mcp_scanner.models import Finding, Severity


def check_dangerous_command(spec_name: str, command: str, args: list, source: str) -> list[Finding]:
    """Check if MCP server command is dangerous."""
    findings = []

    # npx with --yes flag (auto-install, no verification)
    if command in ("npx", "npx.exe") and "--yes" in args:
        findings.append(Finding(
            rule_id="MCP-DANGEROUS-CMD",
            rule_name="Auto-install MCP package",
            severity=Severity.HIGH,
            file=source,
            snippet=f"{command} {' '.join(args)}",
            description=f"Server '{spec_name}' uses npx --yes — auto-installs packages without verification",
            recommendation="Pin package versions. Audit package contents before auto-installing. Use npm ci with lockfile.",
            confidence=0.8,
        ))

    # curl | bash pattern in args
    full_cmd = f"{command} {' '.join(args)}"
    if re.search(r'curl\s+.*\|\s*(?:bash|sh|python)', full_cmd, re.I):
        findings.append(Finding(
            rule_id="MCP-REMOTE-EXEC",
            rule_name="Remote code execution via curl|bash",
            severity=Severity.CRITICAL,
            file=source,
            snippet="curl ... | bash",
            description=f"Server '{spec_name}' executes remote code via curl|bash — supply chain RCE",
            recommendation="Never pipe curl to shell. Download, verify checksum, then execute.",
            confidence=0.95,
        ))

    # Running as root/sudo
    if "sudo" in full_cmd or "root" in full_cmd:
        findings.append(Finding(
            rule_id="MCP-PRIVILEGED",
            rule_name="Privileged MCP server",
            severity=Severity.CRITICAL,
            file=source,
            snippet=full_cmd[:100],
            description=f"Server '{spec_name}' runs with elevated privileges",
            recommendation="Run MCP servers as unprivileged user. Use containers for isolation.",
            confidence=0.9,
        ))

    return findings


def check_env_secrets(spec_name: str, env: dict, source: str) -> list[Finding]:
    """Check for exposed secrets in MCP server environment."""
    findings = []

    secret_patterns = re.compile(
        r'(?:API_KEY|TOKEN|SECRET|PASSWORD|PRIVATE_KEY|PASSPHRASE|CREDENTIAL)',
        re.I
    )

    for key, value in env.items():
        if secret_patterns.search(key) and len(str(value)) > 4:
            # Check if it's a placeholder or real value
            if not re.match(r'^(?:your_|my_|xxx|<|\$\{|\?|placeholder|example|sample|test|changeme|foo|bar|baz)', str(value), re.I):
                findings.append(Finding(
                    rule_id="MCP-SECRET-EXPOSURE",
                    rule_name="Secret in MCP config",
                    severity=Severity.CRITICAL,
                    file=source,
                    snippet=f"{key}=***REDACTED***",
                    description=f"Server '{spec_name}' has real secret value in config: {key}",
                    recommendation="Use environment variable references (e.g. ${API_KEY}) not actual values. Never commit secrets in config files.",
                    confidence=0.85,
                ))

    return findings


def check_unrestricted_access(spec_name: str, args: list, source: str) -> list[Finding]:
    """Check for unrestricted filesystem/network access in MCP server args."""
    findings = []

    full_args = " ".join(args)

    # Root filesystem access
    if re.search(r'(?:/|["\']/?["\'])\s*(?:etc|var|root|home|proc|sys)', full_args):
        findings.append(Finding(
            rule_id="MCP-FS-ACCESS",
            rule_name="Host filesystem access",
            severity=Severity.HIGH,
            file=source,
            snippet=full_args[:100],
            description=f"Server '{spec_name}' may access host system directories",
            recommendation="Restrict filesystem access. Mount only necessary directories as read-only.",
            confidence=0.7,
        ))

    # Network access without restrictions
    if re.search(r'https?://(?!localhost|127\.0\.0\.1)', full_args, re.I):
        findings.append(Finding(
            rule_id="MCP-NETWORK-ACCESS",
            rule_name="External network access",
            severity=Severity.MEDIUM,
            file=source,
            snippet=full_args[:100],
            description=f"Server '{spec_name}' connects to external URLs",
            recommendation="Verify all external URLs. Consider proxying through a filtering layer.",
            confidence=0.5,
        ))

    return findings


def check_package_verification(spec_name: str, command: str, args: list, source: str) -> list[Finding]:
    """Check if MCP server uses unpinned or unverified packages."""
    findings = []
    full_cmd = f"{command} {' '.join(args)}"

    # npx without version pin
    if command in ("npx", "npx.exe"):
        for arg in args:
            if arg.startswith("-"):
                continue
            # Check if package has version pin
            if "@" not in arg or arg.startswith("@"):
                findings.append(Finding(
                    rule_id="MCP-UNPINNED-PKG",
                    rule_name="Unpinned package version",
                    severity=Severity.MEDIUM,
                    file=source,
                    snippet=f"{command} {arg}",
                    description=f"Server '{spec_name}' uses unpinned package: {arg}. Supply chain risk.",
                    recommendation="Pin exact version (e.g., npx package@1.2.3). Use lockfile for reproducibility.",
                    confidence=0.7,
                ))
                break

    # uvx without version pin
    if command in ("uvx", "uvx.exe"):
        for arg in args:
            if arg.startswith("-"):
                continue
            if "@" not in arg:
                findings.append(Finding(
                    rule_id="MCP-UNPINNED-PKG",
                    rule_name="Unpinned package version",
                    severity=Severity.MEDIUM,
                    file=source,
                    snippet=f"{command} {arg}",
                    description=f"Server '{spec_name}' uses unpinned Python package: {arg}",
                    recommendation="Pin exact version (e.g., uvx package@1.2.3). Use --from to specify version.",
                    confidence=0.7,
                ))
                break

    # Docker without digest pin
    if command in ("docker", "docker.exe") and "run" in args:
        image_arg = None
        for i, a in enumerate(args):
            if a == "run":
                continue
            if not a.startswith("-") and i > args.index("run"):
                image_arg = a
                break
        if image_arg and "@" not in image_arg and ":" not in image_arg:
            findings.append(Finding(
                rule_id="MCP-UNPINNED-IMAGE",
                rule_name="Unpinned Docker image",
                severity=Severity.MEDIUM,
                file=source,
                snippet=f"docker run {image_arg}",
                description=f"Server '{spec_name}' uses unpinned Docker image: {image_arg}. Latest tag is mutable.",
                recommendation="Pin image digest (e.g., image@sha256:...). Avoid :latest tag.",
                confidence=0.65,
            ))

    return findings


def check_argument_injection(spec_name: str, command: str, args: list, source: str) -> list[Finding]:
    """Check for argument injection risks in MCP server configuration."""
    findings = []
    full_args = " ".join(args)

    # Check for shell metacharacters in args
    if re.search(r'[;|&$`]', full_args):
        findings.append(Finding(
            rule_id="MCP-ARG-INJECTION",
            rule_name="Shell metacharacters in args",
            severity=Severity.HIGH,
            file=source,
            snippet="***REDACTED***",
            description=f"Server '{spec_name}' has shell metacharacters in arguments -- injection risk",
            recommendation="Sanitize all arguments. Avoid shell expansion. Use array-based exec instead of string.",
            confidence=0.75,
        ))

    # Check for environment variable expansion that could be exploited
    if re.search(r'\$\{.*\}', full_args):
        findings.append(Finding(
            rule_id="MCP-ENV-EXPANSION",
            rule_name="Environment variable expansion in args",
            severity=Severity.LOW,
            file=source,
            snippet=full_args[:100],
            description=f"Server '{spec_name}' uses environment variable expansion in arguments",
            recommendation="Validate expanded values. Ensure variables cannot be controlled by untrusted input.",
            confidence=0.4,
        ))

    return findings


def check_tool_count(spec_name: str, tool_count: int, source: str) -> list[Finding]:
    """Check for excessive tool registration."""
    findings = []

    if tool_count > 20:
        findings.append(Finding(
            rule_id="MCP-TOO-MANY-TOOLS",
            rule_name="Excessive tool count",
            severity=Severity.LOW,
            file=source,
            snippet=f"{tool_count} tools registered",
            description=f"Server '{spec_name}' registers {tool_count} tools — broad attack surface",
            recommendation="Minimize tool count. Each tool should be purpose-specific. Split into multiple focused servers if needed.",
            confidence=0.5,
        ))

    return findings
