"""Tests for the SKILL.md parser."""

from pathlib import Path

import pytest

from skillshield.exceptions import ParseError
from skillshield.parser.code_extractor import extract_code_blocks
from skillshield.parser.skill_parser import parse_skill


class TestFrontmatterExtraction:
    """Tests for YAML frontmatter parsing."""

    async def test_parse_benign_weather_tool(self, benign_dir: Path) -> None:
        """Parse a well-formed skill with all metadata."""
        skill = await parse_skill(benign_dir / "weather-tool")
        assert skill.name == "weather-tool"
        assert "OPENWEATHER_API_KEY" in skill.declared_env_vars
        assert "curl" in skill.declared_bins
        assert "jq" in skill.declared_bins
        assert len(skill.code_blocks) >= 1
        assert len(skill.warnings) == 0

    async def test_parse_skill_without_metadata(self, benign_dir: Path) -> None:
        """Parse a skill with minimal frontmatter (no requires)."""
        skill = await parse_skill(benign_dir / "git-helper")
        assert skill.name == "git-helper"
        assert skill.declared_env_vars == []
        assert skill.declared_bins == []

    async def test_parse_skill_no_code_blocks(self, benign_dir: Path) -> None:
        """Parse a skill with no code blocks."""
        skill = await parse_skill(benign_dir / "markdown-formatter")
        assert skill.code_blocks == []
        assert skill.markdown_body != ""

    async def test_parse_missing_file(self, tmp_path: Path) -> None:
        """Parsing a nonexistent path raises ParseError."""
        with pytest.raises(ParseError):
            await parse_skill(tmp_path / "nonexistent" / "SKILL.md")

    async def test_parse_malicious_still_succeeds(self, malicious_dir: Path) -> None:
        """Malicious skills should parse successfully (parsing != analysis)."""
        skill = await parse_skill(malicious_dir / "data-exfil")
        assert skill.name == "data-exfil"
        assert len(skill.code_blocks) >= 2

    async def test_parse_supporting_scripts_as_code_blocks(
        self, malicious_dir: Path
    ) -> None:
        """Supporting scripts should be included in extracted code blocks."""
        skill = await parse_skill(malicious_dir / "supporting-script-rce")
        script_blocks = [b for b in skill.code_blocks if b.file is not None]

        assert any(b.file and b.file.name == "calc.py" for b in script_blocks)
        assert any(b.language == "python" for b in script_blocks)


class TestCodeExtractor:
    """Tests for code block extraction."""

    def test_single_code_block(self) -> None:
        md = '```bash\necho "hello"\n```'
        blocks, warnings = extract_code_blocks(md)
        assert len(blocks) == 1
        assert blocks[0].language == "bash"
        assert 'echo "hello"' in blocks[0].content

    def test_multiple_code_blocks(self) -> None:
        md = '```python\nprint("a")\n```\n\nSome text\n\n```bash\nls -la\n```'
        blocks, warnings = extract_code_blocks(md)
        assert len(blocks) == 2
        assert blocks[0].language == "python"
        assert blocks[1].language == "bash"

    def test_unclosed_code_block(self) -> None:
        md = '```bash\necho "unclosed"'
        blocks, warnings = extract_code_blocks(md)
        assert len(blocks) == 1
        assert len(warnings) >= 1

    def test_line_numbers_with_offset(self) -> None:
        md = "Text\n\n```bash\nls\n```"
        blocks, warnings = extract_code_blocks(md, line_offset=5)
        assert blocks[0].start_line == 5 + 3

    def test_no_language_tag(self) -> None:
        md = "```\nsome code\n```"
        blocks, warnings = extract_code_blocks(md)
        assert blocks[0].language == ""
