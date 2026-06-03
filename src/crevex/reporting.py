from __future__ import annotations

import json
import textwrap
from html import escape
from pathlib import Path
from typing import Any

from .models import Finding, ScanReport


class TerminalStyle:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    MAGENTA = "\033[35m"


SEVERITY_STYLES = {
    "critical": TerminalStyle.MAGENTA,
    "high": TerminalStyle.RED,
    "medium": TerminalStyle.YELLOW,
    "low": TerminalStyle.CYAN,
    "info": TerminalStyle.GREEN,
}


def report_to_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)


def report_from_json(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def colorize(text: str, style: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{style}{text}{TerminalStyle.RESET}"


def severity_label(severity: str, color: bool) -> str:
    label = severity.upper().ljust(8)
    return colorize(label, SEVERITY_STYLES.get(severity, ""), color)


def wrap_field(label: str, value: str, width: int = 88) -> list[str]:
    prefix = f"  {label}: "
    wrapped = textwrap.wrap(
        value or "-",
        width=max(width - len(prefix), 32),
        break_long_words=False,
        break_on_hyphens=False,
    )
    if not wrapped:
        return [prefix + "-"]
    lines = [prefix + wrapped[0]]
    indent = " " * len(prefix)
    lines.extend(indent + line for line in wrapped[1:])
    return lines


def render_summary(report: ScanReport, color: bool) -> list[str]:
    summary = report.summary()
    labels = ["critical", "high", "medium", "low", "info"]
    rows = []
    for severity in labels:
        count = summary.get(severity, 0)
        rows.append(f"{severity_label(severity, color)} {count}")
    return ["Severity Summary", "  " + "  ".join(rows)]


def render_text(report: ScanReport, color: bool = False, verbosity: str = "normal") -> str:
    title = f"Crevex {report.version} {report.scan_type} report"
    title = colorize(title, TerminalStyle.BOLD, color)
    duration = report.duration_seconds()
    duration_text = f"{duration:.2f}s" if duration is not None else "-"
    lines = [
        title,
        f"Profile: {report.profile}",
        f"Duration: {duration_text}",
        f"Findings: {len(report.findings)} | Errors: {len(report.errors)}",
        "",
        "Targets",
    ]
    lines.extend(f"  - {target}" for target in report.targets)
    lines.extend(["", *render_summary(report, color), "", "Findings"])

    if not report.findings:
        lines.append("  No findings.")
    for index, finding in enumerate(report.findings, start=1):
        label = f"[{finding.severity.upper()}]"
        colored_label = colorize(label, SEVERITY_STYLES.get(finding.severity, ""), color)
        lines.append(f"  {index}. {colored_label} {finding.title}")
        if verbosity == "quiet":
            lines.extend(wrap_field("Target", finding.target))
            lines.append("")
            continue

        lines.extend(wrap_field("Target", finding.target))
        if finding.location:
            lines.extend(wrap_field("Location", finding.location))
        if verbosity == "verbose":
            lines.extend(wrap_field("Check", finding.check_id))
            lines.extend(wrap_field("Finding ID", finding.id))
        lines.extend(wrap_field("Confidence", finding.confidence))
        lines.extend(wrap_field("Evidence", finding.evidence))
        lines.extend(wrap_field("Impact", finding.impact))
        lines.extend(wrap_field("Fix", finding.recommendation))
        if verbosity == "verbose" and finding.references:
            lines.extend(wrap_field("References", ", ".join(finding.references)))
        lines.append("")

    if report.errors:
        lines.append("Errors")
        for error in report.errors:
            lines.append(f"  - {error.target} [{error.check_id}] {error.message}")
    return "\n".join(lines)


def render_html(data: dict[str, Any]) -> str:
    findings = data.get("findings", [])
    rows = []
    for finding in findings:
        rows.append(
            "<tr>"
            f"<td>{escape(finding.get('severity', ''))}</td>"
            f"<td>{escape(finding.get('title', ''))}</td>"
            f"<td>{escape(finding.get('target', ''))}</td>"
            f"<td>{escape(finding.get('location') or '-')}</td>"
            f"<td>{escape(finding.get('confidence', ''))}</td>"
            f"<td>{escape(finding.get('evidence', ''))}</td>"
            f"<td>{escape(finding.get('recommendation', ''))}</td>"
            "</tr>"
        )
    summary = ", ".join(f"{key}: {value}" for key, value in data.get("summary", {}).items())
    duration = data.get("duration_seconds")
    duration_text = f"{duration:.2f}s" if isinstance(duration, (int, float)) else "-"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Crevex Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #202124; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #d0d7de; padding: 8px; vertical-align: top; }}
    th {{ background: #f6f8fa; text-align: left; }}
    .meta {{ margin-bottom: 24px; }}
  </style>
</head>
<body>
  <h1>Crevex Report</h1>
  <div class="meta">
    <p><strong>Scan type:</strong> {escape(data.get("scan_type", ""))}</p>
    <p><strong>Targets:</strong> {escape(", ".join(data.get("targets", [])))}</p>
    <p><strong>Duration:</strong> {escape(duration_text)}</p>
    <p><strong>Summary:</strong> {escape(summary)}</p>
  </div>
  <table>
    <thead>
      <tr>
        <th>Severity</th><th>Title</th><th>Target</th><th>Location</th>
        <th>Confidence</th><th>Evidence</th><th>Recommendation</th>
      </tr>
    </thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</body>
</html>"""


def finding_from_dict(data: dict[str, Any]) -> Finding:
    return Finding(**data)
