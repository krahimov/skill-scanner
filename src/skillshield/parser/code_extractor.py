"""Fenced code block extraction from markdown."""

import re

from skillshield.parser.models import CodeBlock

_FENCE_OPEN = re.compile(r"^(`{3,})(\w*)\s*$")
_FENCE_CLOSE_TEMPLATE = "^`{{{count},}}\\s*$"


def extract_code_blocks(
    markdown: str,
    *,
    line_offset: int = 0,
) -> tuple[list[CodeBlock], list[str]]:
    """Extract fenced code blocks from markdown text."""
    blocks: list[CodeBlock] = []
    warnings: list[str] = []
    lines = markdown.split("\n")

    in_block = False
    fence_len = 0
    language = ""
    block_lines: list[str] = []
    start_line = 0

    for i, line in enumerate(lines):
        line_num = i + 1 + line_offset

        if not in_block:
            m = _FENCE_OPEN.match(line)
            if m:
                in_block = True
                fence_len = len(m.group(1))
                language = m.group(2)
                block_lines = []
                start_line = line_num
        else:
            close_pattern = re.compile(f"^`{{{fence_len},}}\\s*$")
            if close_pattern.match(line):
                content = "\n".join(block_lines)
                blocks.append(CodeBlock(
                    language=language,
                    content=content,
                    start_line=start_line,
                    end_line=line_num,
                ))
                in_block = False
            else:
                block_lines.append(line)

    if in_block:
        content = "\n".join(block_lines)
        blocks.append(CodeBlock(
            language=language,
            content=content,
            start_line=start_line,
            end_line=len(lines) + line_offset,
        ))
        warnings.append(
            f"Unclosed code block starting at line {start_line}"
        )

    return blocks, warnings
