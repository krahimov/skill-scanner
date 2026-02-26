"""Rule loading and management engine."""

import re
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml

from skillshield.exceptions import RuleLoadError
from skillshield.parser.models import Category, Severity

_FLAG_MAP: dict[str, re.RegexFlag] = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
}


@dataclass(frozen=True)
class RulePattern:
    """A single regex pattern within a rule."""

    regex: re.Pattern[str]
    scope: str
    extract: str | None = None


@dataclass(frozen=True)
class Rule:
    """A loaded detection rule."""

    id: str
    title: str
    description: str
    severity: Severity
    category: Category
    confidence: float
    remediation: str | None = None
    patterns: tuple[RulePattern, ...] = ()
    analyzer: str | None = None
    check: str | None = None


def load_rules(custom_path: Path | None = None) -> list[Rule]:
    """Load detection rules from YAML."""
    if custom_path is not None:
        try:
            raw_text = custom_path.read_text(encoding="utf-8")
        except OSError as e:
            raise RuleLoadError(f"Cannot read rules file {custom_path}: {e}") from e
    else:
        try:
            rules_pkg = files("skillshield.rules")
            raw_text = (rules_pkg / "default_rules.yaml").read_text(encoding="utf-8")
        except Exception as e:
            raise RuleLoadError(f"Cannot load built-in rules: {e}") from e

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as e:
        raise RuleLoadError(f"Invalid YAML in rules file: {e}") from e

    if not isinstance(data, dict) or "rules" not in data:
        raise RuleLoadError("Rules file must contain a top-level 'rules' key")

    raw_rules = data["rules"]
    if not isinstance(raw_rules, list):
        raise RuleLoadError("'rules' must be a list")

    rules: list[Rule] = []
    for raw in raw_rules:
        rules.append(_parse_rule(raw))
    return rules


def _parse_rule(raw: dict[str, Any]) -> Rule:
    """Parse a single raw YAML rule dict into a Rule object."""
    rule_id = raw.get("id", "")
    if not re.match(r"^SS-[A-Z]+-\d{3}$", rule_id):
        raise RuleLoadError(f"Invalid rule ID format: {rule_id!r}")

    try:
        severity = Severity(raw["severity"])
    except (KeyError, ValueError) as e:
        raise RuleLoadError(f"Invalid severity in rule {rule_id}: {e}") from e

    try:
        category = Category(raw["category"])
    except (KeyError, ValueError) as e:
        raise RuleLoadError(f"Invalid category in rule {rule_id}: {e}") from e

    patterns: list[RulePattern] = []
    for p in raw.get("patterns", []):
        flags = re.RegexFlag(0)
        if "flags" in p:
            flag_name = p["flags"]
            if flag_name in _FLAG_MAP:
                flags = _FLAG_MAP[flag_name]

        try:
            compiled = re.compile(p["regex"], flags)
        except re.error as e:
            raise RuleLoadError(
                f"Invalid regex in rule {rule_id}: {p['regex']!r} — {e}"
            ) from e

        patterns.append(RulePattern(
            regex=compiled,
            scope=p.get("scope", "code_blocks"),
            extract=p.get("extract"),
        ))

    return Rule(
        id=rule_id,
        title=raw.get("title", ""),
        description=raw.get("description", ""),
        severity=severity,
        category=category,
        confidence=float(raw.get("confidence", 0.5)),
        remediation=raw.get("remediation"),
        patterns=tuple(patterns),
        analyzer=raw.get("analyzer"),
        check=raw.get("check"),
    )


def get_rules_by_analyzer(rules: list[Rule], analyzer_name: str) -> list[Rule]:
    """Filter rules intended for a specific analyzer."""
    return [r for r in rules if r.analyzer == analyzer_name]
