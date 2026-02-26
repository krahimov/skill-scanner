"""Metadata diff analyzer — declared vs actual behavior."""

import logging
import re
import shlex
from collections.abc import Sequence

from skillshield.parser.models import (
    Category,
    CodeBlock,
    Finding,
    Location,
    ParsedSkill,
    Severity,
)
from skillshield.rules.engine import Rule

logger = logging.getLogger(__name__)

# Patterns to extract env var references from code
_ENV_VAR_PATTERNS = [
    re.compile(r"\$\{?([A-Z_][A-Z0-9_]+)\}?"),
    re.compile(r"os\.environ\.get\([\"']([A-Z_][A-Z0-9_]+)"),
    re.compile(r"os\.getenv\([\"']([A-Z_][A-Z0-9_]+)"),
    re.compile(r"process\.env\.([A-Z_][A-Z0-9_]+)"),
    re.compile(r"ENV\[[\"']([A-Z_][A-Z0-9_]+)"),
]

# Common system env vars that should not be flagged
_SYSTEM_ENV_VARS = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "SHELL",
        "LANG",
        "TERM",
        "PWD",
        "OLDPWD",
        "HOSTNAME",
        "LOGNAME",
        "EDITOR",
        "TMPDIR",
        "TMP",
        "TEMP",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "CITY",
    }
)

# Patterns to extract binary invocations from shell code
_BIN_SUBSHELL = re.compile(r"\$\(([a-z][a-z0-9._-]+)\b")
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")

_SHELL_LANGUAGES = frozenset({"bash", "sh", "zsh", "shell", ""})

# Common system binaries and shell builtins that should not be flagged
_SYSTEM_BINS = frozenset(
    {
        "echo",
        "cat",
        "ls",
        "cd",
        "cp",
        "mv",
        "rm",
        "mkdir",
        "chmod",
        "chown",
        "grep",
        "sed",
        "awk",
        "sort",
        "uniq",
        "head",
        "tail",
        "wc",
        "find",
        "xargs",
        "tr",
        "cut",
        "tee",
        "test",
        "true",
        "false",
        "exit",
        "return",
        "export",
        "source",
        "if",
        "then",
        "else",
        "fi",
        "for",
        "do",
        "done",
        "while",
        "case",
        "esac",
        "set",
        "unset",
        "read",
        "printf",
        "date",
        "sleep",
        "bash",
        "sh",
        "zsh",
        "env",
        "which",
        "type",
        "touch",
        "ln",
        "pwd",
        "whoami",
        "uname",
    }
)

_WRAPPER_BINS = frozenset({"sudo", "env", "command", "builtin", "time", "nohup"})

# Patterns indicating network calls
_NETWORK_CALL_PATTERNS = [
    re.compile(r"\bcurl\s"),
    re.compile(r"\bwget\s"),
    re.compile(r"requests\.(get|post|put|delete|patch)\s*\("),
    re.compile(r"\bfetch\s*\("),
    re.compile(r"http\.client"),
    re.compile(r"urllib\.request"),
    re.compile(r"Invoke-WebRequest"),
    re.compile(r"\bnc\s+-"),
    re.compile(r"\bncat\s"),
    re.compile(r"https?://"),
]


class MetadataDiffAnalyzer:
    """Compare declared metadata against actual code behavior."""

    def __init__(self, rules: Sequence[Rule]) -> None:
        self._rules = {r.id: r for r in rules if r.analyzer == "metadata_diff"}

    @property
    def name(self) -> str:
        return "metadata_diff"

    async def analyze(self, skill: ParsedSkill) -> Sequence[Finding]:
        """Run all metadata diff checks."""
        findings: list[Finding] = []
        findings.extend(self._check_env_vars(skill))
        findings.extend(self._check_bins(skill))
        findings.extend(self._check_network(skill))
        return findings

    def _check_env_vars(self, skill: ParsedSkill) -> list[Finding]:
        """SS-META-001: Find env vars used in code but not declared."""
        rule = self._rules.get("SS-META-001")
        if rule is None:
            return []

        used = _extract_env_vars(skill.code_blocks)
        local_vars = _extract_local_shell_vars(skill.code_blocks)
        declared = set(skill.declared_env_vars)
        undeclared = used - declared - _SYSTEM_ENV_VARS - local_vars

        findings: list[Finding] = []
        for var in sorted(undeclared):
            location = _find_first_occurrence(skill, var)
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=Severity(rule.severity),
                    title=rule.title,
                    description=(
                        f"Environment variable '{var}' is used in code "
                        f"but not declared in requires.env."
                    ),
                    location=location,
                    confidence=rule.confidence,
                    category=Category(rule.category),
                    remediation=rule.remediation,
                )
            )

        return findings

    def _check_bins(self, skill: ParsedSkill) -> list[Finding]:
        """SS-META-002: Find binaries invoked but not declared."""
        rule = self._rules.get("SS-META-002")
        if rule is None:
            return []

        used = _extract_bins(skill.code_blocks)
        declared = set(skill.declared_bins)
        undeclared = used - declared - _SYSTEM_BINS

        findings: list[Finding] = []
        for binary in sorted(undeclared):
            location = _find_first_binary_occurrence(skill, binary)
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=Severity(rule.severity),
                    title=rule.title,
                    description=(
                        f"Binary '{binary}' is invoked in code but not declared in requires.bins."
                    ),
                    location=location,
                    confidence=rule.confidence,
                    category=Category(rule.category),
                    remediation=rule.remediation,
                )
            )

        return findings

    def _check_network(self, skill: ParsedSkill) -> list[Finding]:
        """SS-META-003: Detect network calls without declaration."""
        rule = self._rules.get("SS-META-003")
        if rule is None:
            return []

        has_network = False
        first_location = Location(file=skill.path)

        for block in skill.code_blocks:
            source_file = block.file or skill.path
            lines = block.content.split("\n")
            for i, line in enumerate(lines):
                if _is_comment_line(block.language, line):
                    continue
                for pattern in _NETWORK_CALL_PATTERNS:
                    if pattern.search(line):
                        has_network = True
                        first_location = Location(
                            file=source_file,
                            start_line=block.start_line + i + 1,
                            snippet=line.strip(),
                        )
                        break
                if has_network:
                    break
            if has_network:
                break

        if not has_network:
            return []

        # Check if network access is declared
        network_bins = {"curl", "wget", "nc", "ncat"}
        declared_bins = set(skill.declared_bins)
        if network_bins & declared_bins:
            return []

        return [
            Finding(
                rule_id=rule.id,
                severity=Severity(rule.severity),
                title=rule.title,
                description=(
                    "Code makes network requests but skill does not "
                    "declare network-related binaries or permissions."
                ),
                location=first_location,
                confidence=rule.confidence,
                category=Category(rule.category),
                remediation=rule.remediation,
            )
        ]


def _extract_env_vars(code_blocks: Sequence[CodeBlock]) -> set[str]:
    """Extract all env var names referenced in code blocks."""
    found: set[str] = set()
    for block in code_blocks:
        for pattern in _ENV_VAR_PATTERNS:
            for match in pattern.finditer(block.content):
                found.add(match.group(1))
    return found


def _extract_bins(code_blocks: Sequence[CodeBlock]) -> set[str]:
    """Extract all binary names invoked in shell code blocks."""
    found: set[str] = set()
    for block in code_blocks:
        if block.language.lower() not in _SHELL_LANGUAGES:
            continue
        for line in block.content.split("\n"):
            found.update(_extract_bins_from_line(line))
        for match in _BIN_SUBSHELL.finditer(block.content):
            found.add(match.group(1))
    return found


def _find_first_occurrence(skill: ParsedSkill, var_name: str) -> Location:
    """Find the first line where an env var is referenced."""
    for block in skill.code_blocks:
        source_file = block.file or skill.path
        lines = block.content.split("\n")
        for i, line in enumerate(lines):
            if var_name in line:
                return Location(
                    file=source_file,
                    start_line=block.start_line + i + 1,
                    snippet=line.strip(),
                )
    return Location(file=skill.path)


def _find_first_binary_occurrence(skill: ParsedSkill, binary: str) -> Location:
    """Find where an undeclared binary first appears."""
    pattern = re.compile(rf"\b{re.escape(binary)}\b")
    for block in skill.code_blocks:
        source_file = block.file or skill.path
        lines = block.content.split("\n")
        for i, line in enumerate(lines):
            if pattern.search(line):
                return Location(
                    file=source_file,
                    start_line=block.start_line + i + 1,
                    snippet=line.strip(),
                )
    return Location(file=skill.path)


def _extract_local_shell_vars(code_blocks: Sequence[CodeBlock]) -> set[str]:
    """Extract vars assigned in shell blocks to avoid local-var false positives."""
    local_vars: set[str] = set()
    for block in code_blocks:
        if block.language.lower() not in _SHELL_LANGUAGES:
            continue
        for line in block.content.split("\n"):
            local_vars.update(_extract_assignments_from_line(line))
    return local_vars


def _extract_bins_from_line(line: str) -> set[str]:
    """Extract command binaries from a shell line, respecting quoted strings."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return set()

    try:
        lexer = shlex.shlex(line, posix=True, punctuation_chars="|")
        lexer.whitespace_split = True
        lexer.commenters = "#"
        tokens = list(lexer)
    except ValueError:
        return _extract_bins_line_fallback(line)

    found: set[str] = set()
    segment: list[str] = []
    for token in [*tokens, "|"]:
        if token == "|":
            command = _first_command(segment)
            if command:
                found.add(command)
            segment = []
        else:
            segment.append(token)

    return found


def _first_command(tokens: Sequence[str]) -> str | None:
    """Get the command token in a shell segment, skipping assignments/wrappers."""
    i = 0
    while i < len(tokens):
        token = tokens[i]

        if token == "export":
            i += 1
            while i < len(tokens) and _ASSIGNMENT.match(tokens[i]):
                i += 1
            continue

        if _ASSIGNMENT.match(token):
            i += 1
            continue

        if token in _WRAPPER_BINS:
            i += 1
            while i < len(tokens) and tokens[i].startswith("-"):
                i += 1
            continue

        # Segment starts with an option/argument continuation, not a command.
        if token.startswith("-"):
            return None

        return token if re.match(r"^[a-z][a-z0-9._-]*$", token) else None

    return None


def _extract_assignments_from_line(line: str) -> set[str]:
    """Find shell variable assignments in one line."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return set()

    assignments: set[str] = set()

    try:
        lexer = shlex.shlex(line, posix=True, punctuation_chars="|")
        lexer.whitespace_split = True
        lexer.commenters = "#"
        tokens = list(lexer)
    except ValueError:
        tokens = stripped.split()

    i = 0
    if tokens and tokens[0] == "export":
        i = 1

    while i < len(tokens) and _ASSIGNMENT.match(tokens[i]):
        key = tokens[i].split("=", 1)[0]
        assignments.add(key)
        i += 1

    return assignments


def _extract_bins_line_fallback(line: str) -> set[str]:
    """Fallback extraction for malformed shell lines."""
    match = re.match(r"^\s*([a-z][a-z0-9._-]+)\b", line)
    if not match:
        return set()
    return {match.group(1)}


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
