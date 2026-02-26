"""SkillShield CLI entry point."""

import asyncio
import json
import logging
import time
from pathlib import Path

import click

from skillshield import __version__
from skillshield.analyzers.llm_analyzer import LLMAnalyzer
from skillshield.analyzers.metadata_diff import MetadataDiffAnalyzer
from skillshield.analyzers.network_analyzer import NetworkAnalyzer
from skillshield.analyzers.static_rules import StaticRulesAnalyzer
from skillshield.config import Config
from skillshield.parser.models import Finding, ScanResult
from skillshield.parser.skill_parser import parse_skill
from skillshield.reporters.terminal import TerminalReporter

logger = logging.getLogger(__name__)
_SKILL_FILENAME = "skill.md"


@click.group()
@click.version_option(version=__version__)
def main() -> None:
    """SkillShield - Security scanner for AI agent skills."""


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["terminal", "json"]),
    default="terminal",
    help="Output format.",
)
@click.option(
    "--severity",
    type=str,
    default=None,
    help="Comma-separated severity filter (e.g., critical,high).",
)
@click.option(
    "--rules",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to custom rules YAML.",
)
@click.option(
    "--recursive/--no-recursive",
    default=False,
    help="Recursively scan all SKILL.md files under PATH.",
)
@click.option(
    "--llm/--no-llm",
    "use_llm",
    default=True,
    help="Enable or disable LLM semantic analysis.",
)
@click.option(
    "--deep/--no-deep",
    default=False,
    help="Use deep LLM profile model instead of bulk model.",
)
def scan(
    path: Path,
    output_format: str,
    severity: str | None,
    rules: Path | None,
    recursive: bool,
    use_llm: bool,
    deep: bool,
) -> None:
    """Scan a SKILL.md file or skill directory for security issues."""
    asyncio.run(_scan_async(path, output_format, severity, rules, recursive, use_llm, deep))


async def _scan_async(
    path: Path,
    output_format: str,
    severity_filter: str | None,
    rules_path: Path | None,
    recursive: bool,
    use_llm: bool,
    deep: bool,
) -> None:
    """Async implementation of the scan command."""
    config = Config.load(rules_path=rules_path)
    targets = _resolve_targets(path, recursive)
    if recursive and not targets:
        raise click.ClickException(f"No SKILL.md files found under: {path}")

    results = [
        await _scan_single_target(
            target=target,
            config=config,
            severity_filter=severity_filter,
            use_llm=use_llm,
            deep=deep,
        )
        for target in targets
    ]

    if output_format == "terminal":
        reporter = TerminalReporter()
        for result in results:
            reporter.report(result)
        if len(results) > 1:
            _print_multi_summary(results)
    elif output_format == "json":
        if len(results) == 1:
            click.echo(results[0].model_dump_json(indent=2))
        else:
            payload = {
                "results": [r.model_dump(mode="json") for r in results],
                "summary": _build_multi_summary(results),
            }
            click.echo(json.dumps(payload, indent=2))

    if any(f.severity.value in ("critical", "high") for result in results for f in result.findings):
        raise SystemExit(1)


def _compute_risk_score(findings: list[Finding]) -> int:
    """Compute a 0-100 risk score from findings."""
    weights = {
        "critical": 25,
        "high": 15,
        "medium": 5,
        "low": 2,
        "info": 0,
    }
    score = sum(weights.get(f.severity.value, 0) for f in findings)
    return min(score, 100)


def _resolve_targets(path: Path, recursive: bool) -> list[Path]:
    """Resolve the list of scan targets."""
    if path.is_file():
        return [path]

    if recursive:
        return sorted(
            p for p in path.rglob("*") if p.is_file() and p.name.lower() == _SKILL_FILENAME
        )

    return [path]


async def _scan_single_target(
    target: Path,
    config: Config,
    severity_filter: str | None,
    use_llm: bool,
    deep: bool,
) -> ScanResult:
    """Scan one file/directory target and build a ScanResult."""
    start_time = time.monotonic()
    skill = await parse_skill(target)
    if skill.warnings:
        for warning in skill.warnings:
            logger.warning("Parser: %s", warning)

    analyzers = [
        StaticRulesAnalyzer(config.rules),
        NetworkAnalyzer(config.rules),
        MetadataDiffAnalyzer(config.rules),
    ]
    if use_llm:
        model = config.llm_model_deep if deep else config.llm_model_bulk
        analyzers.append(
            LLMAnalyzer(
                model=model,
                api_key=config.llm_api_key,
                timeout_s=config.llm_timeout_s,
                max_output_tokens=config.llm_max_output_tokens,
            )
        )
    analyzer_results = await asyncio.gather(*(analyzer.analyze(skill) for analyzer in analyzers))

    findings: list[Finding] = []
    analyzers_run: list[str] = []
    for analyzer, analyzer_findings in zip(analyzers, analyzer_results, strict=True):
        findings.extend(analyzer_findings)
        analyzers_run.append(analyzer.name)

    if severity_filter:
        allowed = {s.strip().lower() for s in severity_filter.split(",")}
        findings = [f for f in findings if f.severity.value in allowed]

    return ScanResult(
        skill=skill,
        findings=findings,
        risk_score=_compute_risk_score(findings),
        scan_duration_ms=int((time.monotonic() - start_time) * 1000),
        analyzers_run=analyzers_run,
    )


def _build_multi_summary(results: list[ScanResult]) -> dict[str, object]:
    """Build a compact summary across many scanned skills."""
    severity_counts: dict[str, int] = {}
    total_findings = 0
    failed_skills = 0

    for result in results:
        skill_failed = False
        for finding in result.findings:
            total_findings += 1
            severity = finding.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            if severity in {"critical", "high"}:
                skill_failed = True
        if skill_failed:
            failed_skills += 1

    return {
        "skills_scanned": len(results),
        "skills_with_high_or_critical": failed_skills,
        "total_findings": total_findings,
        "severity_counts": severity_counts,
    }


def _print_multi_summary(results: list[ScanResult]) -> None:
    """Print a one-line summary after recursive scans."""
    summary = _build_multi_summary(results)
    click.echo(
        (
            "\nScanned "
            f"{summary['skills_scanned']} skills. "
            f"Findings: {summary['total_findings']}. "
            f"High/Critical in {summary['skills_with_high_or_critical']} skills."
        ),
        err=True,
    )
