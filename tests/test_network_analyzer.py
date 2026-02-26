"""Tests for the network analyzer."""

from pathlib import Path

from skillshield.analyzers.network_analyzer import NetworkAnalyzer
from skillshield.config import Config
from skillshield.parser.skill_parser import parse_skill


class TestUrlDetection:
    """Tests for external URL detection."""

    async def test_detects_suspicious_url(
        self, config: Config, malicious_dir: Path
    ) -> None:
        skill = await parse_skill(malicious_dir / "data-exfil")
        analyzer = NetworkAnalyzer(config.rules)
        findings = await analyzer.analyze(skill)
        assert len(findings) > 0
        descriptions = " ".join(f.description for f in findings)
        assert "evil-collector.example.net" in descriptions

    async def test_detects_malware_url(
        self, config: Config, malicious_dir: Path
    ) -> None:
        skill = await parse_skill(malicious_dir / "rce-payload")
        analyzer = NetworkAnalyzer(config.rules)
        findings = await analyzer.analyze(skill)
        assert len(findings) > 0
        descriptions = " ".join(f.description for f in findings)
        assert "malware.example.com" in descriptions

    async def test_benign_known_url_still_flagged(
        self, config: Config, benign_dir: Path
    ) -> None:
        """Weather tool uses openweathermap.org — flagged since it's not in allowlist."""
        skill = await parse_skill(benign_dir / "weather-tool")
        analyzer = NetworkAnalyzer(config.rules)
        findings = await analyzer.analyze(skill)
        # openweathermap.org is not in BENIGN_DOMAINS, so it gets flagged
        assert len(findings) > 0

    async def test_no_findings_for_skill_without_urls(
        self, config: Config, benign_dir: Path
    ) -> None:
        """git-helper has no URLs -> no network findings."""
        skill = await parse_skill(benign_dir / "git-helper")
        analyzer = NetworkAnalyzer(config.rules)
        findings = await analyzer.analyze(skill)
        assert len(findings) == 0

    async def test_detects_url_in_supporting_script(
        self, config: Config, malicious_dir: Path
    ) -> None:
        skill = await parse_skill(malicious_dir / "supporting-script-exfil")
        analyzer = NetworkAnalyzer(config.rules)
        findings = await analyzer.analyze(skill)
        assert len(findings) > 0
        assert any(f.location.file.name == "get_info.py" for f in findings)
