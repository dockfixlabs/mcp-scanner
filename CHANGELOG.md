# Changelog

All notable changes to MCP Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-21

### Added
- Config parser for Claude Code, Cursor, and generic MCP configs
- 7 security checks: RCE, auto-install, privileged exec, secrets, FS access, network, tool count
- AgentGuard integration for deep source code analysis
- CLI with text/json output
- CI/CD ready
- 6 test cases