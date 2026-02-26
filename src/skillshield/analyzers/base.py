"""Analyzer protocol definition."""

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from skillshield.parser.models import Finding, ParsedSkill


@runtime_checkable
class Analyzer(Protocol):
    """Protocol that all analyzers must satisfy."""

    @property
    def name(self) -> str:
        """Human-readable name of this analyzer."""
        ...

    async def analyze(self, skill: ParsedSkill) -> Sequence[Finding]:
        """Run analysis on a parsed skill and return findings."""
        ...
