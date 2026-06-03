from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Any

from .models import Finding, ScanReport


def report_to_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)


def report_from_json(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def render_text(report: ScanReport) -> str:
    lines = [
        f"Crevex {report.version} {report.scan_type} report",
        f"Targets: {', '.join(report.targets) if report.targets else '-'}",
        "Summary: "
        + ", ".join(f"{severity}={count}" for severity, count in report.summary().items()),
        "",
    ]
    if not report.findings:
        lines.append("No findings.")
    for finding in report.findings:
        lines.extend(
            [
                f"[{finding.severity.upper()}] {finding.title}",
                f"  Target: {finding.target}",
                f"  Location: {finding.location or '-'}",
                f"  Confidence: {finding.confidence}",
                f"  Evidence: {finding.evidence}",
                f"  Recommendation: {finding.recommendation}",
                "",
            ]
        )
    if report.errors:
        lines.append("Errors:")
        for error in report.errors:
            lines.append(f"  {error.target} {error.check_id}: {error.message}")
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
