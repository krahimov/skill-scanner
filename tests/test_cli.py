"""Tests for the CLI entry point."""

import json
from pathlib import Path

from click.testing import CliRunner

from skillshield.cli import main


class TestScanCommand:
    """Tests for the scan command."""

    def test_scan_benign_skill_exits_zero(self, benign_dir: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(benign_dir / "markdown-formatter")])
        assert result.exit_code == 0

    def test_scan_malicious_skill_exits_nonzero(self, malicious_dir: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(malicious_dir / "data-exfil")])
        assert result.exit_code != 0

    def test_scan_json_output(self, benign_dir: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", str(benign_dir / "markdown-formatter"), "--format", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "risk_score" in data
        assert "findings" in data

    def test_scan_recursive_json_output(self, benign_dir: Path) -> None:
        runner = CliRunner()
        fixtures_root = benign_dir.parent
        result = runner.invoke(
            main,
            ["scan", str(fixtures_root), "--recursive", "--format", "json"],
        )
        # Fixture tree includes malicious examples, so non-zero exit is expected.
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert "results" in data
        assert "summary" in data
        assert data["summary"]["skills_scanned"] >= 1

    def test_scan_nonexistent_path(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(tmp_path / "nope")])
        assert result.exit_code != 0

    def test_scan_no_llm_does_not_initialize_llm(
        self,
        benign_dir: Path,
        monkeypatch,
    ) -> None:
        class ExplodingLLM:
            def __init__(self, **_: object) -> None:
                raise AssertionError("LLM analyzer must not initialize when --no-llm is set")

        monkeypatch.setattr("skillshield.cli.LLMAnalyzer", ExplodingLLM)

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", str(benign_dir / "markdown-formatter"), "--no-llm"],
        )
        assert result.exit_code == 0

    def test_scan_uses_bulk_model_by_default(
        self,
        benign_dir: Path,
        monkeypatch,
    ) -> None:
        selected_models: list[str] = []

        class DummyLLM:
            def __init__(
                self,
                *,
                model: str,
                api_key: str | None,
                timeout_s: int,
                max_output_tokens: int,
            ) -> None:
                selected_models.append(model)
                _ = (api_key, timeout_s, max_output_tokens)

            @property
            def name(self) -> str:
                return "llm_semantic"

            async def analyze(self, skill):
                _ = skill
                return []

        monkeypatch.setenv("SKILLSHIELD_LLM_MODEL_BULK", "bulk-model")
        monkeypatch.setenv("SKILLSHIELD_LLM_MODEL_DEEP", "deep-model")
        monkeypatch.setattr("skillshield.cli.LLMAnalyzer", DummyLLM)

        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(benign_dir / "markdown-formatter")])
        assert result.exit_code == 0
        assert selected_models == ["bulk-model"]

    def test_scan_uses_deep_model_when_flag_set(
        self,
        benign_dir: Path,
        monkeypatch,
    ) -> None:
        selected_models: list[str] = []

        class DummyLLM:
            def __init__(
                self,
                *,
                model: str,
                api_key: str | None,
                timeout_s: int,
                max_output_tokens: int,
            ) -> None:
                selected_models.append(model)
                _ = (api_key, timeout_s, max_output_tokens)

            @property
            def name(self) -> str:
                return "llm_semantic"

            async def analyze(self, skill):
                _ = skill
                return []

        monkeypatch.setenv("SKILLSHIELD_LLM_MODEL_BULK", "bulk-model")
        monkeypatch.setenv("SKILLSHIELD_LLM_MODEL_DEEP", "deep-model")
        monkeypatch.setattr("skillshield.cli.LLMAnalyzer", DummyLLM)

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", str(benign_dir / "markdown-formatter"), "--deep"],
        )
        assert result.exit_code == 0
        assert selected_models == ["deep-model"]

    def test_version_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert "0.1.0" in result.output
