"""Core models for MCP Server security scanning."""

from __future__ import annotations
from enum import Enum
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Finding(BaseModel):
    rule_id: str
    rule_name: str
    severity: Severity
    file: str
    line: int = 0
    snippet: str = ""
    description: str
    recommendation: str
    confidence: float = Field(ge=0.0, le=1.0)


class ScanResult(BaseModel):
    target: str
    files_scanned: int
    findings: list[Finding] = Field(default_factory=list)
    scan_duration_ms: int = 0

    @property
    def clean(self) -> bool:
        return len(self.findings) == 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)


class MCPToolSpec(BaseModel):
    """Parsed MCP tool definition from config or source."""
    name: str
    description: str = ""
    command: str = ""
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=list)
    source_file: str = ""


class MCPServerConfig(BaseModel):
    """Parsed MCP server configuration (e.g. from claude_code_config.json)."""
    servers: dict[str, MCPToolSpec] = Field(default_factory=dict)
    source_file: str = ""
