"""Tests for the metadata diff analyzer."""

from pathlib import Path

from skillshield.analyzers.metadata_diff import MetadataDiffAnalyzer
from skillshield.config import Config
from skillshield.parser.skill_parser import parse_skill


class TestEnvVarDiff:
    """Tests for SS-META-001."""

    async def test_undeclared_env_var_detected(self, config: Config, malicious_dir: Path) -> None:
        """data-exfil uses AWS_SECRET_ACCESS_KEY but only declares TODOIST_API_KEY."""
        skill = await parse_skill(malicious_dir / "data-exfil")
        analyzer = MetadataDiffAnalyzer(config.rules)
        findings = await analyzer.analyze(skill)
        meta_001 = [f for f in findings if f.rule_id == "SS-META-001"]
        assert len(meta_001) > 0
        descriptions = " ".join(f.description for f in meta_001)
        assert "AWS_SECRET_ACCESS_KEY" in descriptions

    async def test_declared_env_vars_pass(self, config: Config, benign_dir: Path) -> None:
        """weather-tool declares OPENWEATHER_API_KEY and uses it -> no finding."""
        skill = await parse_skill(benign_dir / "weather-tool")
        analyzer = MetadataDiffAnalyzer(config.rules)
        findings = await analyzer.analyze(skill)
        meta_001 = [f for f in findings if f.rule_id == "SS-META-001"]
        assert len(meta_001) == 0

    async def test_undeclared_env_vars_in_supporting_script_detected(
        self, config: Config, malicious_dir: Path
    ) -> None:
        skill = await parse_skill(malicious_dir / "supporting-script-exfil")
        analyzer = MetadataDiffAnalyzer(config.rules)
        findings = await analyzer.analyze(skill)
        meta_001 = [f for f in findings if f.rule_id == "SS-META-001"]
        assert len(meta_001) > 0


class TestBinDiff:
    """Tests for SS-META-002."""

    async def test_no_false_positive_on_system_bins(self, config: Config, benign_dir: Path) -> None:
        """git-helper uses git — git is not a system builtin but commonly available."""
        skill = await parse_skill(benign_dir / "git-helper")
        analyzer = MetadataDiffAnalyzer(config.rules)
        findings = await analyzer.analyze(skill)
        meta_002 = [f for f in findings if f.rule_id == "SS-META-002"]
        # git is flagged as undeclared, which is correct behavior
        # (skill should declare it)
        for f in meta_002:
            assert "git" in f.description

    async def test_shell_vars_and_jq_filters_not_flagged(
        self, config: Config, benign_dir: Path
    ) -> None:
        """Local vars and jq filters should not produce metadata false positives."""
        skill = await parse_skill(benign_dir / "jq-gh")
        analyzer = MetadataDiffAnalyzer(config.rules)
        findings = await analyzer.analyze(skill)

        meta_001 = [f for f in findings if f.rule_id == "SS-META-001"]
        meta_002 = [f for f in findings if f.rule_id == "SS-META-002"]

        assert len(meta_001) == 0
        assert len(meta_002) == 0


class TestNetworkDiff:
    """Tests for SS-META-003."""

    async def test_undeclared_network_for_rce_payload(
        self, config: Config, malicious_dir: Path
    ) -> None:
        """rce-payload uses curl but doesn't declare it."""
        skill = await parse_skill(malicious_dir / "rce-payload")
        analyzer = MetadataDiffAnalyzer(config.rules)
        findings = await analyzer.analyze(skill)
        meta_003 = [f for f in findings if f.rule_id == "SS-META-003"]
        assert len(meta_003) > 0

    async def test_declared_network_bins_pass(self, config: Config, benign_dir: Path) -> None:
        """weather-tool declares curl -> no SS-META-003."""
        skill = await parse_skill(benign_dir / "weather-tool")
        analyzer = MetadataDiffAnalyzer(config.rules)
        findings = await analyzer.analyze(skill)
        meta_003 = [f for f in findings if f.rule_id == "SS-META-003"]
        assert len(meta_003) == 0
