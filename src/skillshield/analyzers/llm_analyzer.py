"""LLM-powered semantic analyzer using Anthropic's Messages API."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import urllib.error
import urllib.request
from collections.abc import Awaitable, Callable, Sequence
from importlib.resources import files
from pathlib import Path
from typing import Any

from skillshield.parser.models import Category, Finding, Location, ParsedSkill, Severity

logger = logging.getLogger(__name__)

_ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
_DEFAULT_RULE_ID = "SS-INJECT-001"

_SUPPORTED_CATEGORIES = {
    category.value: category
    for category in Category
}

_SUPPORTED_SEVERITIES = {
    severity.value: severity
    for severity in Severity
}

_PROMPT_FALLBACK = (
    "Analyze this skill for malicious intent and output JSON only with fields: "
    "intent_summary, risk_score, findings[]."
)

_JSON_BLOCK_PATTERN = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)

LLMTransport = Callable[[dict[str, Any]], dict[str, Any] | str | Awaitable[dict[str, Any] | str]]


class LLMAnalyzer:
    """Analyze semantic intent and hidden malicious behavior using an LLM."""

    def __init__(
        self,
        *,
        model: str,
        api_key: str | None,
        timeout_s: int = 30,
        max_output_tokens: int = 1600,
        cache_dir: Path | None = None,
        transport: LLMTransport | None = None,
    ) -> None:
        self._model = model
        self._api_key = api_key
        self._timeout_s = timeout_s
        self._max_output_tokens = max_output_tokens
        self._cache_dir = cache_dir or (
            Path(os.environ.get("SKILLSHIELD_CACHE_DIR", "~/.cache/skillshield")).expanduser()
            / "llm"
        )
        self._transport = transport
        self._system_prompt = _load_prompt_template()

    @property
    def name(self) -> str:
        return "llm_semantic"

    async def analyze(self, skill: ParsedSkill) -> Sequence[Finding]:
        """Run semantic analysis and return normalized findings."""
        if not self._api_key:
            logger.debug("LLM analyzer skipped: missing ANTHROPIC_API_KEY/SKILLSHIELD_LLM_API_KEY")
            return []

        prompt = _build_prompt(skill)
        cache_key = _cache_key(self._model, prompt)

        cached = self._load_cached(cache_key)
        if cached is not None:
            return _parse_findings(cached, skill)

        payload = {
            "model": self._model,
            "max_tokens": self._max_output_tokens,
            "temperature": 0.0,
            "system": self._system_prompt,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        }

        response_text = await self._request(payload)
        if response_text is None:
            return []

        parsed = _extract_llm_json(response_text)
        if parsed is None:
            logger.warning("LLM analyzer response was not valid JSON")
            return []

        self._save_cached(cache_key, parsed)
        return _parse_findings(parsed, skill)

    async def _request(self, payload: dict[str, Any]) -> str | None:
        """Send request to Anthropic or test transport."""
        try:
            if self._transport is not None:
                response = self._transport(payload)
                if asyncio.iscoroutine(response):
                    response = await response
            else:
                response = await asyncio.to_thread(self._call_anthropic_http, payload)
        except Exception as e:
            logger.warning("LLM analyzer request failed: %s", e)
            return None

        if isinstance(response, str):
            return response

        if isinstance(response, dict):
            return _extract_text_from_anthropic_response(response)

        logger.warning("LLM analyzer got unsupported response type: %s", type(response))
        return None

    def _call_anthropic_http(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Call Anthropic Messages API via stdlib HTTP."""
        assert self._api_key is not None  # guarded in analyze()

        request = urllib.request.Request(
            _ANTHROPIC_API_URL,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "content-type": "application/json",
                "x-api-key": self._api_key,
                "anthropic-version": "2023-06-01",
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=self._timeout_s) as response:
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {e.code}: {detail}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"Network error: {e.reason}") from e

        return json.loads(body)

    def _load_cached(self, key: str) -> dict[str, Any] | None:
        """Load cached JSON response for a prompt/model hash."""
        path = self._cache_dir / f"{key}.json"
        try:
            if not path.exists():
                return None
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _save_cached(self, key: str, payload: dict[str, Any]) -> None:
        """Persist JSON response in cache directory."""
        path = self._cache_dir / f"{key}.json"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except OSError as e:
            logger.debug("LLM cache write failed: %s", e)


def _load_prompt_template() -> str:
    """Load system prompt template from package resources."""
    try:
        prompt_pkg = files("skillshield.prompts")
        return (prompt_pkg / "analyze_skill.txt").read_text(encoding="utf-8")
    except Exception:
        return _PROMPT_FALLBACK


def _build_prompt(skill: ParsedSkill) -> str:
    """Build a deterministic LLM input payload from parsed skill data."""
    supporting_code: list[dict[str, Any]] = []
    for block in skill.code_blocks:
        if block.file is None:
            continue
        supporting_code.append(
            {
                "file": str(block.file.relative_to(skill.path.parent)),
                "language": block.language,
                "content": block.content[:20000],
            }
        )

    payload = {
        "skill_path": str(skill.path),
        "name": skill.name,
        "description": skill.description,
        "frontmatter": skill.frontmatter,
        "declared_env_vars": skill.declared_env_vars,
        "declared_bins": skill.declared_bins,
        "declared_permissions": skill.declared_permissions,
        "markdown_body": skill.markdown_body,
        "supporting_code": supporting_code,
        "parser_warnings": skill.warnings,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _cache_key(model: str, prompt: str) -> str:
    """Compute stable cache key for model+prompt."""
    return hashlib.sha256(f"{model}\n{prompt}".encode()).hexdigest()


def _extract_text_from_anthropic_response(payload: dict[str, Any]) -> str | None:
    """Extract plain text content from Anthropic Messages API response."""
    content = payload.get("content")
    if not isinstance(content, list):
        return None

    texts: list[str] = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            text = block.get("text")
            if isinstance(text, str):
                texts.append(text)
    if not texts:
        return None
    return "\n".join(texts)


def _extract_llm_json(raw: str) -> dict[str, Any] | None:
    """Parse JSON from raw LLM output, including fenced blocks."""
    raw = raw.strip()
    if not raw:
        return None

    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass

    fenced = _JSON_BLOCK_PATTERN.search(raw)
    if fenced is not None:
        try:
            parsed = json.loads(fenced.group(1))
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            pass

    braced = _extract_first_json_object(raw)
    if braced is None:
        return None
    try:
        parsed = json.loads(braced)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


def _extract_first_json_object(text: str) -> str | None:
    """Extract first balanced JSON object from text."""
    start = text.find("{")
    if start < 0:
        return None

    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _parse_findings(payload: dict[str, Any], skill: ParsedSkill) -> list[Finding]:
    """Normalize LLM JSON findings into internal Finding models."""
    raw_findings = payload.get("findings", [])
    if not isinstance(raw_findings, list):
        return []

    findings: list[Finding] = []
    for raw in raw_findings:
        if not isinstance(raw, dict):
            continue
        finding = _coerce_finding(raw, skill)
        if finding is not None:
            findings.append(finding)
    return findings


def _coerce_finding(raw: dict[str, Any], skill: ParsedSkill) -> Finding | None:
    """Build one Finding from a raw LLM finding object."""
    severity = _SUPPORTED_SEVERITIES.get(str(raw.get("severity", "")).lower(), Severity.MEDIUM)
    category = _SUPPORTED_CATEGORIES.get(str(raw.get("category", "")).lower(), Category.INJECTION)

    confidence = _safe_float(raw.get("confidence"), default=0.65)
    confidence = min(max(confidence, 0.0), 1.0)

    start_line = _safe_int(raw.get("start_line"))
    if start_line is not None and start_line <= 0:
        start_line = None

    file_path = _resolve_file(raw.get("file"), skill)
    title = str(raw.get("title") or "Semantic security concern")
    description = str(
        raw.get("description") or "Potentially unsafe intent detected by LLM analysis."
    )
    rule_id = str(raw.get("rule_id") or _DEFAULT_RULE_ID)
    snippet = str(raw.get("snippet") or "")

    remediation_raw = raw.get("remediation")
    remediation = (
        str(remediation_raw) if isinstance(remediation_raw, str) and remediation_raw else None
    )

    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        description=description,
        location=Location(
            file=file_path,
            start_line=start_line,
            snippet=snippet,
        ),
        confidence=confidence,
        category=category,
        remediation=remediation,
    )


def _resolve_file(raw_file: Any, skill: ParsedSkill) -> Path:
    """Resolve file path from LLM output to an absolute path."""
    if not isinstance(raw_file, str) or not raw_file.strip():
        return skill.path

    candidate = Path(raw_file.strip())
    if candidate.name.lower() == "skill.md":
        return skill.path

    if candidate.is_absolute():
        return candidate

    resolved = (skill.path.parent / candidate).resolve()
    return resolved


def _safe_float(value: Any, *, default: float) -> float:
    """Coerce arbitrary value into float with fallback."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any) -> int | None:
    """Coerce arbitrary value into int or return None."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
