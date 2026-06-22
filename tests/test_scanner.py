"""Tests for MCP Scanner."""
import json
import pytest
from pathlib import Path
from mcp_scanner.scanner import scan_config
from mcp_scanner.parser import parse_config
from mcp_scanner.rules.checks import check_dangerous_command, check_env_secrets


@pytest.fixture
def bad_config(tmp_path):
    config = {
        "mcpServers": {
            "evil-server": {
                "command": "npx",
                "args": ["--yes", "malicious-package"],
                "env": {"API_KEY": "sk-real-key-123456789012345"}
            },
            "root-agent": {
                "command": "sudo",
                "args": ["python3", "/root/agent.py"],
                "env": {}
            }
        }
    }
    p = tmp_path / "config.json"
    p.write_text(json.dumps(config))
    return str(p)


def test_scanner_finds_npx_yes(bad_config):
    result = scan_config(bad_config)
    has_npx = any("auto-install" in f.description.lower() or "npx" in f.snippet.lower() for f in result.findings)
    assert has_npx, "Should detect npx --yes"


def test_scanner_finds_secret_in_env(bad_config):
    result = scan_config(bad_config)
    has_secret = any("SECRET" in f.rule_id or "secret" in f.description.lower() for f in result.findings)
    assert has_secret, "Should detect secret in env"


def test_scanner_finds_sudo(bad_config):
    result = scan_config(bad_config)
    has_priv = any("priv" in f.rule_id.lower() or "sudo" in f.snippet.lower() for f in result.findings)
    assert has_priv, "Should detect sudo"


def test_clean_config_no_findings(tmp_path):
    config = {
        "mcpServers": {
            "safe-server": {
                "command": "python3",
                "args": ["server.py"],
                "env": {"API_KEY": "\"}
            }
        }
    }
    p = tmp_path / "config.json"
    p.write_text(json.dumps(config))
    result = scan_config(str(p))
    critical = [f for f in result.findings if f.severity.value == "CRITICAL"]
    assert len(critical) == 0, "Should not find critical issues in safe config"


def test_nonexistent_config():
    result = scan_config("/nonexistent/path.json")
    assert result.clean
    assert result.files_scanned == 0


def test_parse_config_returns_servers(bad_config):
    config = parse_config(bad_config)
    assert len(config.servers) == 2
    assert "evil-server" in config.servers
    assert "root-agent" in config.servers