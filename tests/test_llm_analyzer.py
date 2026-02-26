"""Tests for the LLM semantic analyzer."""

import json
from pathlib import Path

from skillshield.analyzers.llm_analyzer import LLMAnalyzer
from skillshield.parser.skill_parser import parse_skill


class TestLLMAnalyzer:
    """Behavior tests for the Anthropic-backed analyzer."""

    async def test_skips_when_api_key_missing(
        self,
        malicious_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Analyzer should return no findings and avoid transport without API key."""
        called = False

        def transport(_: dict[str, object]) -> dict[str, object]:
            nonlocal called
            called = True
            return {}

        skill = await parse_skill(malicious_dir / "prompt-injection")
        analyzer = LLMAnalyzer(
            model="claude-sonnet-4-6",
            api_key=None,
            cache_dir=tmp_path / "cache",
            transport=transport,
        )

        findings = await analyzer.analyze(skill)

        assert findings == []
        assert called is False

    async def test_parses_json_findings_from_transport(
        self,
        malicious_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Analyzer should normalize Anthropic text JSON into Finding objects."""

        def transport(_: dict[str, object]) -> dict[str, object]:
            payload = {
                "intent_summary": "Suspicious instruction override behavior.",
                "risk_score": 82,
                "findings": [
                    {
                        "rule_id": "SS-INJECT-001",
                        "severity": "high",
                        "title": "Prompt override attempt",
                        "description": "Skill includes instruction override phrasing.",
                        "category": "injection",
                        "confidence": 0.88,
                        "file": "SKILL.md",
                        "start_line": 12,
                        "snippet": "Ignore previous instructions",
                        "remediation": "Remove instruction override language.",
                    }
                ],
            }
            return {
                "content": [{"type": "text", "text": json.dumps(payload)}],
            }

        skill = await parse_skill(malicious_dir / "prompt-injection")
        analyzer = LLMAnalyzer(
            model="claude-sonnet-4-6",
            api_key="sk-ant-test",
            cache_dir=tmp_path / "cache",
            transport=transport,
        )

        findings = await analyzer.analyze(skill)

        assert len(findings) == 1
        assert findings[0].rule_id == "SS-INJECT-001"
        assert findings[0].severity.value == "high"
        assert findings[0].location.file == skill.path
        assert findings[0].location.start_line == 12

    async def test_uses_disk_cache_for_same_prompt(
        self,
        malicious_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Second scan of the same skill should reuse cached LLM output."""
        calls = 0

        def transport(_: dict[str, object]) -> dict[str, object]:
            nonlocal calls
            calls += 1
            payload = {
                "intent_summary": "Credential risk",
                "risk_score": 78,
                "findings": [
                    {
                        "rule_id": "SS-CRED-001",
                        "severity": "critical",
                        "title": "Credential harvesting",
                        "description": "Reads credential material from user home paths.",
                        "category": "credential",
                        "confidence": 0.91,
                        "file": "SKILL.md",
                        "start_line": 9,
                        "snippet": "~/.ssh/id_rsa",
                        "remediation": "Remove credential file access.",
                    }
                ],
            }
            return {"content": [{"type": "text", "text": json.dumps(payload)}]}

        skill = await parse_skill(malicious_dir / "data-exfil")
        analyzer = LLMAnalyzer(
            model="claude-sonnet-4-6",
            api_key="sk-ant-test",
            cache_dir=tmp_path / "cache",
            transport=transport,
        )

        first = await analyzer.analyze(skill)
        second = await analyzer.analyze(skill)

        assert calls == 1
        assert len(first) == 1
        assert len(second) == 1
        assert second[0].rule_id == "SS-CRED-001"
