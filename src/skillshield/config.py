"""SkillShield configuration management."""

import logging
import os
from dataclasses import dataclass
from pathlib import Path

from skillshield.rules.engine import Rule, load_rules


@dataclass
class Config:
    """Runtime configuration for SkillShield."""

    rules_path: Path | None
    log_level: str
    llm_api_key: str | None
    llm_model_bulk: str
    llm_model_deep: str
    llm_timeout_s: int
    llm_max_output_tokens: int
    rules: list[Rule]

    @classmethod
    def load(cls, rules_path: Path | None = None) -> "Config":
        """Load configuration from environment and optional overrides."""
        resolved_rules_path = rules_path or _env_rules_path()
        log_level = os.environ.get("SKILLSHIELD_LOG_LEVEL", "INFO")
        llm_api_key = (
            os.environ.get("ANTHROPIC_API_KEY")
            or os.environ.get("SKILLSHIELD_LLM_API_KEY")
        )
        llm_model_bulk = os.environ.get(
            "SKILLSHIELD_LLM_MODEL_BULK",
            "claude-sonnet-4-6",
        )
        llm_model_deep = os.environ.get(
            "SKILLSHIELD_LLM_MODEL_DEEP",
            "claude-sonnet-4-6",
        )
        llm_timeout_s = _safe_int_env("SKILLSHIELD_LLM_TIMEOUT_S", default=30)
        llm_max_output_tokens = _safe_int_env(
            "SKILLSHIELD_LLM_MAX_OUTPUT_TOKENS",
            default=1600,
        )
        logging.basicConfig(
            level=getattr(logging, log_level.upper(), logging.INFO),
            format="%(levelname)s: %(message)s",
        )
        rules = load_rules(resolved_rules_path)
        return cls(
            rules_path=resolved_rules_path,
            log_level=log_level,
            llm_api_key=llm_api_key,
            llm_model_bulk=llm_model_bulk,
            llm_model_deep=llm_model_deep,
            llm_timeout_s=llm_timeout_s,
            llm_max_output_tokens=llm_max_output_tokens,
            rules=rules,
        )


def _env_rules_path() -> Path | None:
    """Read SKILLSHIELD_RULES_PATH from environment."""
    raw = os.environ.get("SKILLSHIELD_RULES_PATH")
    return Path(raw) if raw else None


def _safe_int_env(name: str, *, default: int) -> int:
    """Read an integer environment variable with fallback."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default
