"""Custom exceptions for SkillShield."""


class SkillShieldError(Exception):
    """Base exception for all SkillShield errors."""


class ParseError(SkillShieldError):
    """Raised when SKILL.md parsing fails irrecoverably."""


class FrontmatterError(ParseError):
    """Raised when YAML frontmatter is invalid or missing."""


class RuleLoadError(SkillShieldError):
    """Raised when rules YAML cannot be loaded or is malformed."""


class AnalyzerError(SkillShieldError):
    """Raised when an analyzer encounters an unexpected failure."""


class ConfigError(SkillShieldError):
    """Raised when configuration is invalid."""
