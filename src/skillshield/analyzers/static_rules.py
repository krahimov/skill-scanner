"""Static regex-based rules analyzer."""

import logging
from collections.abc import Sequence

from skillshield.parser.models import (
    Category,
    Finding,
    Location,
    ParsedSkill,
    Severity,
)
from skillshield.rules.engine import Rule, RulePattern

logger = logging.getLogger(__name__)


class StaticRulesAnalyzer:
    """Analyzer that matches regex patterns against skill content."""

    def __init__(self, rules: Sequence[Rule]) -> None:
        self._rules = [r for r in rules if r.patterns and r.analyzer is None]

    @property
    def name(self) -> str:
        return "static_rules"

    async def analyze(self, skill: ParsedSkill) -> Sequence[Finding]:
        """Run all static rules against the parsed skill."""
        findings: list[Finding] = []
        for rule in self._rules:
            findings.extend(self._check_rule(rule, skill))
        return findings

    def _check_rule(self, rule: Rule, skill: ParsedSkill) -> list[Finding]:
        """Check a single rule against the skill."""
        findings: list[Finding] = []
        seen: set[tuple[str, str, int | None]] = set()

        for pattern in rule.patterns:
            if pattern.scope == "code_blocks":
                for f in self._match_code_blocks(rule, pattern, skill):
                    key = (rule.id, str(f.location.file), f.location.start_line)
                    if key not in seen:
                        seen.add(key)
                        findings.append(f)
            elif pattern.scope == "full_content":
                for f in self._match_full_content(rule, pattern, skill):
                    key = (rule.id, str(f.location.file), f.location.start_line)
                    if key not in seen:
                        seen.add(key)
                        findings.append(f)

        return findings

    def _match_code_blocks(
        self,
        rule: Rule,
        pattern: RulePattern,
        skill: ParsedSkill,
    ) -> list[Finding]:
        """Match a pattern against all code blocks."""
        findings: list[Finding] = []

        for block in skill.code_blocks:
            source_file = block.file or skill.path
            lines = block.content.split("\n")
            for i, line in enumerate(lines):
                if _is_comment_line(block.language, line):
                    continue
                match = pattern.regex.search(line)
                if match:
                    abs_line = block.start_line + i + 1
                    findings.append(Finding(
                        rule_id=rule.id,
                        severity=Severity(rule.severity),
                        title=rule.title,
                        description=rule.description,
                        location=Location(
                            file=source_file,
                            start_line=abs_line,
                            snippet=line.strip(),
                        ),
                        confidence=rule.confidence,
                        category=Category(rule.category),
                        remediation=rule.remediation,
                    ))

        return findings

    def _match_full_content(
        self,
        rule: Rule,
        pattern: RulePattern,
        skill: ParsedSkill,
    ) -> list[Finding]:
        """Match a pattern against the full file content."""
        findings: list[Finding] = []
        full_text = skill.markdown_body
        lines = full_text.split("\n")

        for i, line in enumerate(lines):
            match = pattern.regex.search(line)
            if match:
                findings.append(Finding(
                    rule_id=rule.id,
                    severity=Severity(rule.severity),
                    title=rule.title,
                    description=rule.description,
                    location=Location(
                        file=skill.path,
                        start_line=i + 1,
                        snippet=line.strip()[:200],
                    ),
                    confidence=rule.confidence,
                    category=Category(rule.category),
                    remediation=rule.remediation,
                ))

        return findings


def _is_comment_line(language: str, line: str) -> bool:
    """Detect line comments for common script languages."""
    stripped = line.strip()
    if not stripped:
        return False

    lang = language.lower()
    if lang in {"python", "bash", "sh", "zsh", "shell", "", "ruby", "powershell"}:
        return stripped.startswith("#")
    if lang in {"javascript", "typescript"}:
        return stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*")
    return False
