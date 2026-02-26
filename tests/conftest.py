"""Shared test fixtures for SkillShield tests."""

from pathlib import Path

import pytest

from skillshield.config import Config

FIXTURES_DIR = Path(__file__).parent / "fixtures"
BENIGN_DIR = FIXTURES_DIR / "benign"
MALICIOUS_DIR = FIXTURES_DIR / "malicious"


@pytest.fixture
def config() -> Config:
    """Load default configuration with built-in rules."""
    return Config.load()


@pytest.fixture
def benign_dir() -> Path:
    """Path to benign fixtures directory."""
    return BENIGN_DIR


@pytest.fixture
def malicious_dir() -> Path:
    """Path to malicious fixtures directory."""
    return MALICIOUS_DIR
