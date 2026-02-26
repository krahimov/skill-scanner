"""SKILL.md file parser."""

import asyncio
import logging
from pathlib import Path
from typing import Any

import yaml

from skillshield.exceptions import ParseError
from skillshield.parser.code_extractor import extract_code_blocks
from skillshield.parser.models import CodeBlock, InstallSpec, ParsedSkill

logger = logging.getLogger(__name__)

_SKILL_FILENAMES = {"skill.md", "SKILL.md", "Skill.md"}
_MAX_SUPPORTING_CODE_BYTES = 512 * 1024
_SUPPORTED_CODE_EXTENSIONS = {
    ".py": "python",
    ".sh": "bash",
    ".bash": "bash",
    ".zsh": "zsh",
    ".js": "javascript",
    ".ts": "typescript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ps1": "powershell",
    ".rb": "ruby",
    ".go": "go",
}


async def parse_skill(path: Path) -> ParsedSkill:
    """Parse a SKILL.md file into a structured representation."""
    resolved = _resolve_path(path)
    content = await _read_file(resolved)

    frontmatter_str, markdown_body, frontmatter_lines = _split_frontmatter(content)

    frontmatter: dict[str, Any] = {}
    warnings: list[str] = []

    if frontmatter_str:
        try:
            parsed = yaml.safe_load(frontmatter_str)
            if isinstance(parsed, dict):
                frontmatter = parsed
            else:
                warnings.append("Frontmatter is not a YAML mapping")
        except yaml.YAMLError as e:
            warnings.append(f"Failed to parse YAML frontmatter: {e}")
    else:
        warnings.append("No YAML frontmatter found")

    env_vars, bins, permissions, install_specs = _extract_metadata(frontmatter)

    line_offset = frontmatter_lines
    markdown_code_blocks, extract_warnings = extract_code_blocks(
        markdown_body, line_offset=line_offset
    )
    warnings.extend(extract_warnings)

    name = frontmatter.get("name", "")
    description = frontmatter.get("description", "")
    if not name:
        warnings.append("Skill name not found in frontmatter")
        name = resolved.parent.name if resolved.parent.name != "." else resolved.stem

    supporting_files = _discover_supporting_files(resolved)
    supporting_code_blocks, supporting_warnings = await _extract_supporting_code_blocks(
        supporting_files
    )
    warnings.extend(supporting_warnings)

    return ParsedSkill(
        name=name,
        description=description,
        path=resolved,
        frontmatter=frontmatter,
        declared_env_vars=env_vars,
        declared_bins=bins,
        declared_permissions=permissions,
        markdown_body=markdown_body,
        code_blocks=[*markdown_code_blocks, *supporting_code_blocks],
        install_specs=install_specs,
        supporting_files=supporting_files,
        warnings=warnings,
    )


def _resolve_path(path: Path) -> Path:
    """Resolve a path to a SKILL.md file."""
    if path.is_file():
        return path
    if path.is_dir():
        for name in _SKILL_FILENAMES:
            candidate = path / name
            if candidate.is_file():
                return candidate
        raise ParseError(f"No SKILL.md found in directory: {path}")
    raise ParseError(f"Path does not exist: {path}")


async def _read_file(path: Path) -> str:
    """Read a file asynchronously."""
    try:
        return await asyncio.to_thread(path.read_text, encoding="utf-8")
    except OSError as e:
        raise ParseError(f"Cannot read file {path}: {e}") from e


def _split_frontmatter(content: str) -> tuple[str, str, int]:
    """Split YAML frontmatter from markdown body.

    Returns (frontmatter_yaml, markdown_body, total_frontmatter_lines).
    """
    lines = content.split("\n")

    if not lines or lines[0].strip() != "---":
        return "", content, 0

    end_index = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end_index = i
            break

    if end_index is None:
        return "", content, 0

    frontmatter_str = "\n".join(lines[1:end_index])
    markdown_body = "\n".join(lines[end_index + 1 :])
    total_lines = end_index + 1

    return frontmatter_str, markdown_body, total_lines


def _extract_metadata(
    frontmatter: dict[str, Any],
) -> tuple[list[str], list[str], list[str], list[InstallSpec]]:
    """Extract env vars, bins, permissions, and install specs from frontmatter."""
    env_vars: list[str] = []
    bins: list[str] = []
    permissions: list[str] = []
    install_specs: list[InstallSpec] = []

    # Flat AgentSkills format: requires.env, requires.bins
    requires = frontmatter.get("requires", {})
    if isinstance(requires, dict):
        env_vars.extend(_as_str_list(requires.get("env", [])))
        bins.extend(_as_str_list(requires.get("bins", [])))

    # Nested OpenClaw format: metadata.openclaw.requires.*
    for ns in ("openclaw", "clawdbot", "clawdis"):
        meta_ns = frontmatter.get("metadata", {})
        if not isinstance(meta_ns, dict):
            break
        ns_data = meta_ns.get(ns, {})
        if not isinstance(ns_data, dict):
            continue

        ns_requires = ns_data.get("requires", {})
        if isinstance(ns_requires, dict):
            env_vars.extend(_as_str_list(ns_requires.get("env", [])))
            bins.extend(_as_str_list(ns_requires.get("bins", [])))

        permissions.extend(_as_str_list(ns_data.get("permissions", [])))

        raw_install = ns_data.get("install", [])
        if isinstance(raw_install, list):
            for item in raw_install:
                if isinstance(item, dict):
                    spec = InstallSpec(
                        kind=str(item.get("kind", "")),
                        package=str(item.get("package", "")),
                        bins=_as_str_list(item.get("bins", [])),
                    )
                    install_specs.append(spec)
                    bins.extend(spec.bins)

    # Deduplicate while preserving order
    env_vars = list(dict.fromkeys(env_vars))
    bins = list(dict.fromkeys(bins))
    permissions = list(dict.fromkeys(permissions))

    return env_vars, bins, permissions, install_specs


def _discover_supporting_files(skill_path: Path) -> list[Path]:
    """Find all non-SKILL.md files under the skill directory."""
    skill_dir = skill_path.parent
    supporting: list[Path] = []
    if not skill_dir.is_dir():
        return supporting
    for child in sorted(skill_dir.rglob("*")):
        if child.is_file() and child.name.lower() != "skill.md":
            supporting.append(child)
    return supporting


async def _extract_supporting_code_blocks(
    supporting_files: list[Path],
) -> tuple[list[CodeBlock], list[str]]:
    """Extract pseudo code blocks from script-like supporting files."""
    tasks = [_read_supporting_code_file(path) for path in supporting_files]
    results = await asyncio.gather(*tasks)

    blocks: list[CodeBlock] = []
    warnings: list[str] = []
    for file_blocks, file_warnings in results:
        blocks.extend(file_blocks)
        warnings.extend(file_warnings)
    return blocks, warnings


async def _read_supporting_code_file(path: Path) -> tuple[list[CodeBlock], list[str]]:
    """Read one supporting file and return extracted pseudo code blocks."""
    language = _language_for_supporting_file(path)
    if language is None:
        return [], []

    try:
        size = await asyncio.to_thread(path.stat)
    except OSError as e:
        return [], [f"Cannot stat supporting file {path}: {e}"]

    if size.st_size > _MAX_SUPPORTING_CODE_BYTES:
        return [], [f"Skipping large supporting code file (>512KB): {path}"]

    try:
        content = await asyncio.to_thread(path.read_text, encoding="utf-8")
    except UnicodeDecodeError:
        return [], [f"Skipping non-text supporting file: {path}"]
    except OSError as e:
        return [], [f"Cannot read supporting file {path}: {e}"]

    if not content.strip():
        return [], []

    line_count = max(1, len(content.split("\n")))
    return [
        CodeBlock(
            language=language,
            content=content,
            start_line=1,
            end_line=line_count,
            file=path,
        )
    ], []


def _language_for_supporting_file(path: Path) -> str | None:
    """Infer language for a supporting code file."""
    ext = path.suffix.lower()
    if ext in _SUPPORTED_CODE_EXTENSIONS:
        return _SUPPORTED_CODE_EXTENSIONS[ext]

    if ext:
        return None

    try:
        first_line = path.read_text(encoding="utf-8").split("\n", 1)[0]
    except (OSError, UnicodeDecodeError):
        return None

    if first_line.startswith("#!/"):
        if "python" in first_line:
            return "python"
        if any(shell in first_line for shell in ("bash", "sh", "zsh")):
            return "bash"

    return None


def _as_str_list(value: Any) -> list[str]:
    """Coerce a value to a list of strings."""
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        return [value]
    return []
