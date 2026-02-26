"""Rich terminal reporter for scan results."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from skillshield.parser.models import Finding, ScanResult, Severity

SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_SYMBOLS: dict[Severity, str] = {
    Severity.CRITICAL: "[!]",
    Severity.HIGH: "[H]",
    Severity.MEDIUM: "[M]",
    Severity.LOW: "[L]",
    Severity.INFO: "[i]",
}


class TerminalReporter:
    """Format and display scan results in the terminal."""

    def __init__(self) -> None:
        self._console = Console(stderr=True)

    def report(self, result: ScanResult) -> None:
        """Display a full scan report."""
        self._print_header(result)
        self._print_findings_table(result)
        self._print_summary(result)

    def _print_header(self, result: ScanResult) -> None:
        """Print the skill info header."""
        header = Text()
        header.append(f"Skill: {result.skill.name}\n", style="bold")
        header.append(f"Path:  {result.skill.path}\n")
        header.append(f"Analyzers: {', '.join(result.analyzers_run)}\n")
        header.append(f"Duration: {result.scan_duration_ms}ms")
        self._console.print(Panel(header, title="SkillShield Scan"))

    def _print_findings_table(self, result: ScanResult) -> None:
        """Print findings as a formatted table."""
        if not result.findings:
            self._console.print(
                "\n[bold green]No findings.[/bold green] Skill looks clean.\n"
            )
            return

        severity_order = list(Severity)
        sorted_findings = sorted(
            result.findings,
            key=lambda f: severity_order.index(f.severity),
        )

        table = Table(title="Findings", show_lines=True, expand=True)
        table.add_column("Severity", width=12)
        table.add_column("Rule", width=16)
        table.add_column("Title", ratio=2)
        table.add_column("Location", ratio=1)
        table.add_column("Conf", width=6)

        for finding in sorted_findings:
            sev_style = SEVERITY_COLORS[finding.severity]
            sev_text = Text(
                f"{SEVERITY_SYMBOLS[finding.severity]} {finding.severity.value.upper()}",
                style=sev_style,
            )
            loc = str(finding.location.file.name)
            if finding.location.start_line:
                loc += f":{finding.location.start_line}"

            table.add_row(
                sev_text,
                finding.rule_id,
                finding.title,
                loc,
                f"{finding.confidence:.0%}",
            )

        self._console.print(table)

        for finding in sorted_findings:
            if finding.severity in (Severity.CRITICAL, Severity.HIGH):
                self._print_finding_detail(finding)

    def _print_finding_detail(self, finding: Finding) -> None:
        """Print detailed info for a single finding."""
        style = SEVERITY_COLORS[finding.severity]
        content = Text()
        content.append(f"{finding.description}\n\n")
        if finding.location.snippet:
            content.append("Code:\n", style="bold")
            content.append(f"  {finding.location.snippet}\n\n")
        if finding.remediation:
            content.append("Remediation: ", style="bold")
            content.append(finding.remediation)
        self._console.print(
            Panel(
                content,
                title=f"{finding.rule_id}: {finding.title}",
                border_style=style,
            )
        )

    def _print_summary(self, result: ScanResult) -> None:
        """Print the risk score summary."""
        score = result.risk_score
        if score >= 75:
            score_style = "bold red"
            verdict = "CRITICAL RISK"
        elif score >= 50:
            score_style = "red"
            verdict = "HIGH RISK"
        elif score >= 25:
            score_style = "yellow"
            verdict = "MODERATE RISK"
        elif score > 0:
            score_style = "cyan"
            verdict = "LOW RISK"
        else:
            score_style = "bold green"
            verdict = "CLEAN"

        summary = Text()
        summary.append("\nRisk Score: ", style="bold")
        summary.append(f"{score}/100", style=score_style)
        summary.append(f"  ({verdict})", style=score_style)
        summary.append(f"\nTotal Findings: {len(result.findings)}")

        for sev in Severity:
            count = sum(1 for f in result.findings if f.severity == sev)
            if count > 0:
                summary.append(
                    f"\n  {sev.value}: {count}", style=SEVERITY_COLORS[sev]
                )

        self._console.print(Panel(summary, title="Summary"))
