"""Network target detection analyzer."""

import ipaddress
import logging
import re
from collections.abc import Sequence
from urllib.parse import urlparse

from skillshield.parser.models import (
    Category,
    CodeBlock,
    Finding,
    Location,
    ParsedSkill,
    Severity,
)
from skillshield.rules.engine import Rule

logger = logging.getLogger(__name__)

URL_PATTERN = re.compile(r"https?://[^\s\"'`\])<>]{3,}", re.IGNORECASE)

IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

BENIGN_DOMAINS = frozenset({
    "github.com",
    "raw.githubusercontent.com",
    "githubusercontent.com",
    "npmjs.org",
    "npmjs.com",
    "pypi.org",
    "example.com",
    "localhost",
    "api.github.com",
    "registry.npmjs.org",
})

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


class NetworkAnalyzer:
    """Detect external URLs, domains, and IPs in code blocks."""

    def __init__(self, rules: Sequence[Rule]) -> None:
        self._rules = {r.id: r for r in rules}

    @property
    def name(self) -> str:
        return "network"

    async def analyze(self, skill: ParsedSkill) -> Sequence[Finding]:
        """Scan code blocks for network targets."""
        findings: list[Finding] = []
        for block in skill.code_blocks:
            findings.extend(self._scan_block(block, skill))
        return findings

    def _scan_block(
        self, block: CodeBlock, skill: ParsedSkill
    ) -> list[Finding]:
        """Scan a single code block for URLs and IPs."""
        findings: list[Finding] = []
        lines = block.content.split("\n")
        source_file = block.file or skill.path

        for i, line in enumerate(lines):
            if _is_comment_line(block.language, line):
                continue
            abs_line = block.start_line + i + 1

            for url_match in URL_PATTERN.finditer(line):
                url = url_match.group(0)
                domain = _extract_domain(url)
                if domain and domain not in BENIGN_DOMAINS:
                    findings.append(Finding(
                        rule_id="SS-EXFIL-001",
                        severity=Severity.CRITICAL,
                        title="External URL detected in code",
                        description=f"Code contacts external domain: {domain} ({url})",
                        location=Location(
                            file=source_file,
                            start_line=abs_line,
                            snippet=line.strip(),
                        ),
                        confidence=0.80,
                        category=Category.NETWORK,
                        remediation="Verify this URL is expected and declare it in skill metadata.",
                    ))

            for ip_match in IP_PATTERN.finditer(line):
                ip_str = ip_match.group(1)
                if not _is_private_ip(ip_str):
                    findings.append(Finding(
                        rule_id="SS-EXFIL-001",
                        severity=Severity.HIGH,
                        title="Public IP address in code",
                        description=f"Code references public IP: {ip_str}",
                        location=Location(
                            file=source_file,
                            start_line=abs_line,
                            snippet=line.strip(),
                        ),
                        confidence=0.70,
                        category=Category.NETWORK,
                        remediation=(
                            "Avoid hardcoded IP addresses. "
                            "Use domain names declared in metadata."
                        ),
                    ))

        return findings


def _extract_domain(url: str) -> str:
    """Extract the domain portion from a URL."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        return hostname if hostname else ""
    except ValueError:
        return ""


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is in a private/loopback range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in network for network in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def _is_comment_line(language: str, line: str) -> bool:
    """Detect line comments for common script languages."""
    stripped = line.strip()
    if not stripped:
        return False

    lang = language.lower()
    if lang in {"python", "bash", "sh", "zsh", "shell", "", "ruby", "powershell"}:
        return stripped.startswith("#")
    if lang in {"javascript", "typescript"}:
        return stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*")
    return False
