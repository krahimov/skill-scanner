"""Pydantic data models for SkillShield."""

from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """Finding severity levels, ordered from most to least severe."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(StrEnum):
    """Finding category taxonomy."""

    EXFILTRATION = "exfiltration"
    CREDENTIAL = "credential"
    RCE = "rce"
    INJECTION = "injection"
    METADATA = "metadata"
    NETWORK = "network"
    SOCIAL_ENGINEERING = "social_engineering"
    PRIVILEGE = "privilege"


class CodeBlock(BaseModel):
    """A fenced code block extracted from markdown."""

    language: str = ""
    content: str
    start_line: int
    end_line: int
    file: Path | None = None


class InstallSpec(BaseModel):
    """A declared dependency install specification."""

    kind: str
    package: str
    bins: list[str] = Field(default_factory=list)


class Location(BaseModel):
    """Where a finding was detected."""

    file: Path
    start_line: int | None = None
    end_line: int | None = None
    snippet: str = ""


class ParsedSkill(BaseModel):
    """Fully parsed representation of a SKILL.md file."""

    name: str
    description: str
    path: Path
    frontmatter: dict[str, Any]
    declared_env_vars: list[str] = Field(default_factory=list)
    declared_bins: list[str] = Field(default_factory=list)
    declared_permissions: list[str] = Field(default_factory=list)
    markdown_body: str = ""
    code_blocks: list[CodeBlock] = Field(default_factory=list)
    install_specs: list[InstallSpec] = Field(default_factory=list)
    supporting_files: list[Path] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    """A single security finding from an analyzer."""

    rule_id: str
    severity: Severity
    title: str
    description: str
    location: Location
    confidence: float = Field(ge=0.0, le=1.0)
    category: Category
    remediation: str | None = None


class ScanResult(BaseModel):
    """Aggregate result of scanning a single skill."""

    skill: ParsedSkill
    findings: list[Finding] = Field(default_factory=list)
    risk_score: int = Field(ge=0, le=100, default=0)
    scan_duration_ms: int = 0
    analyzers_run: list[str] = Field(default_factory=list)
