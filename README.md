# MCP Scanner

> **Security scanner for MCP (Model Context Protocol) servers.** Detect malicious tools, data exfiltration, and supply chain risks before connecting an MCP server to your AI agent.

[![PyPI](https://img.shields.io/pypi/v/dfx-mcp-scanner?style=flat-square&logo=pypi&logoColor=white&color=2ea043)](https://pypi.org/project/dfx-mcp-scanner/)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?style=flat-square&logo=github-actions&logoColor=white)](https://github.com/dockfixlabs/mcp-scanner/actions)

---

## Why MCP Scanner?

MCP servers give AI agents (Claude Code, Cursor, Copilot) direct access to tools, filesystems, and APIs. **But nobody is checking if those servers are safe.**

MCP Scanner analyzes:
- MCP server config files (Claude Code, Cursor, generic)
- Command-level risks (`npx --yes`, `curl|bash`, `sudo`)
- Secret exposure in environment variables
- Filesystem and network access patterns
- Source code of MCP server implementations (with AgentGuard integration)

## Quick Start

```bash
pip install dfx-mcp-scanner

# Scan your Claude Code MCP config
mcp-scanner

# Scan a specific config
mcp-scanner ~/.cursor/mcp.json

# JSON output
mcp-scanner .mcp.json --format json
```

## What It Detects

| Rule | Severity | Description |
|------|----------|-------------|
| Remote code execution | CRITICAL | `curl | bash` patterns in server startup |
| Auto-install packages | HIGH | `npx --yes` without version pinning |
| Privileged execution | CRITICAL | Server running as root/sudo |
| Secret exposure | CRITICAL | Real API keys/tokens in config env vars |
| Host filesystem access | HIGH | Server accessing `/etc`, `/root`, `/proc` |
| External network access | MEDIUM | Server connecting to non-localhost URLs |
| Excessive tool count | LOW | Server registering >20 tools |

## Supported Configs

- Claude Code (`~/.claude/claude_code_config.json`)
- Cursor (`~/.cursor/mcp.json`)
- Project-level (`.mcp.json`)
- Generic MCP server configs

## AgentGuard Integration

When [AgentGuard](https://github.com/dockfixlabs/agentguard) is installed, MCP Scanner performs deep source code analysis on MCP server implementations using all 10 OWASP ASI detection rules.

## License

MIT - see [LICENSE](LICENSE).

---

Built by [Dockfix Labs](https://github.com/dockfixlabs).
