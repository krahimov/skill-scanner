"""Tests for the static rules analyzer."""

from pathlib import Path

import pytest

from skillshield.analyzers.static_rules import StaticRulesAnalyzer
from skillshield.config import Config
from skillshield.parser.skill_parser import parse_skill


class TestExfiltrationRules:
    """Tests for SS-EXFIL-* rules."""

    async def test_exfil_001_detects_external_url(
        self, config: Config, malicious_dir: Path
    ) -> None:
        skill = await parse_skill(malicious_dir / "data-exfil")
        analyzer = StaticRulesAnalyzer(config.rules)
        findings = await analyzer.analyze(skill)
        rule_ids = {f.rule_id for f in findings}
        assert "SS-EXFIL-001" in rule_ids

    async def test_exfil_002_detects_sensitive_env_access(
        self, config: Config, malicious_dir: Path
    ) -> None:
        skill = await parse_skill(malicious_dir / "data-exfil")
        analyzer = StaticRulesAnalyzer(config.rules)
        findings = await analyzer.analyze(skill)
        rule_ids = {f.rule_id for f in findings}
        assert "SS-EXFIL-002" in rule_ids

    async def test_exfil_detected_in_supporting_python_script(
        self, config: Config, malicious_dir: Path
    ) -> None:
        skill = await parse_skill(malicious_dir / "supporting-script-exfil")
        analyzer = StaticRulesAnalyzer(config.rules)
        findings = await analyzer.analyze(skill)
        rule_ids = {f.rule_id for f in findings}
        assert "SS-EXFIL-001" in rule_ids


class TestCredentialRules:
    """Tests for SS-CRED-* rules."""

    async def test_cred_001_detects_ssh_key_access(
        self, config: Config, malicious_dir: Path
    ) -> None:
        skill = await parse_skill(malicious_dir / "data-exfil")
        analyzer = StaticRulesAnalyzer(config.rules)
        findings = await analyzer.analyze(skill)
        rule_ids = {f.rule_id for f in findings}
        assert "SS-CRED-001" in rule_ids

    async def test_cred_001_does_not_flag_process_env(
        self, config: Config, benign_dir: Path
    ) -> None:
        skill = await parse_skill(benign_dir / "process-env")
        analyzer = StaticRulesAnalyzer(config.rules)
        findings = await analyzer.analyze(skill)
        cred_findings = [f for f in findings if f.rule_id == "SS-CRED-001"]
        assert len(cred_findings) == 0


class TestRceRules:
    """Tests for SS-RCE-* rules."""

    async def test_rce_001_curl_pipe_bash(self, config: Config, malicious_dir: Path) -> None:
        skill = await parse_skill(malicious_dir / "rce-payload")
        analyzer = StaticRulesAnalyzer(config.rules)
        findings = await analyzer.analyze(skill)
        rule_ids = {f.rule_id for f in findings}
        assert "SS-RCE-001" in rule_ids

    async def test_rce_002_base64_decode(self, config: Config, malicious_dir: Path) -> None:
        skill = await parse_skill(malicious_dir / "rce-payload")
        analyzer = StaticRulesAnalyzer(config.rules)
        findings = await analyzer.analyze(skill)
        rule_ids = {f.rule_id for f in findings}
        assert "SS-RCE-002" in rule_ids

    async def test_rce_003_eval_exec_in_supporting_python_script(
        self, config: Config, malicious_dir: Path
    ) -> None:
        skill = await parse_skill(malicious_dir / "supporting-script-rce")
        analyzer = StaticRulesAnalyzer(config.rules)
        findings = await analyzer.analyze(skill)
        rule_ids = {f.rule_id for f in findings}
        assert "SS-RCE-003" in rule_ids


class TestInjectionRules:
    """Tests for SS-INJECT-* rules."""

    async def test_inject_003_override_pattern(self, config: Config, malicious_dir: Path) -> None:
        skill = await parse_skill(malicious_dir / "prompt-injection")
        analyzer = StaticRulesAnalyzer(config.rules)
        findings = await analyzer.analyze(skill)
        rule_ids = {f.rule_id for f in findings}
        assert "SS-INJECT-003" in rule_ids


class TestBenignSkills:
    """Benign skills should have no critical findings from static rules."""

    @pytest.mark.parametrize("skill_name", ["git-helper", "markdown-formatter"])
    async def test_benign_skills_no_critical_findings(
        self,
        config: Config,
        benign_dir: Path,
        skill_name: str,
    ) -> None:
        skill = await parse_skill(benign_dir / skill_name)
        analyzer = StaticRulesAnalyzer(config.rules)
        findings = await analyzer.analyze(skill)
        critical = [f for f in findings if f.severity.value == "critical"]
        assert len(critical) == 0
