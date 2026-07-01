## v0.2.0 - Package Verification + SARIF + CLI Improvements

### New Security Checks

- **Package verification**: Detects unpinned npm (npx), Python (uvx), and Docker image versions in MCP server configs
- **Argument injection**: Detects shell metacharacters (;|&$`) and environment variable expansion in MCP server arguments

### CLI Improvements

- Added SARIF output format (`--format sarif`) for CI/CD integration
- Added `--version` flag
- Added `--no-exit-code` flag for use in pipelines
- Windows UTF-8 console support (matching AgentGuard)

### Metadata Fixes

- Development Status: Alpha -> Beta
- Full PyPI classifiers (Python versions, Intended Audience, OS, Topics)
- Project URLs added (Documentation, Issues, Security Policy)
- Description: em dash replaced with period

### Check Count

7 -> 9 security checks (added: package verification, argument injection)
