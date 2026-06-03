from __future__ import annotations

from pathlib import Path

from . import __version__
from .checks import build_checks
from .models import ScanError, ScanReport, ScanTarget
from .targets import load_targets


def make_code_target(path: str) -> ScanTarget:
    root = Path(path)
    if not root.exists():
        raise ValueError(f"code path does not exist: {path}")
    return ScanTarget(raw=str(root), kind="code", host=str(root))


def run_scan(
    targets: list[str],
    target_file: str | None = None,
    code_path: str | None = None,
    scan_type: str = "scan",
    profile: str = "standard",
    include: set[str] | None = None,
    exclude: set[str] | None = None,
) -> ScanReport:
    report = ScanReport.start(version=__version__, scan_type=scan_type, profile=profile)
    normalized: list[ScanTarget] = []

    if scan_type in {"scan", "audit"}:
        normalized.extend(load_targets(targets, target_file=target_file))
    if scan_type in {"code-scan", "audit"}:
        if not code_path and targets and scan_type == "code-scan":
            code_path = targets[0]
        if not code_path:
            raise ValueError("code path is required for source-code scanning")
        normalized.append(make_code_target(code_path))

    checks = build_checks(scan_type, include=include, exclude=exclude)
    report.targets = [target.display for target in normalized]

    for target in normalized:
        for check in checks:
            if target.kind not in check.target_kinds:
                continue
            try:
                report.findings.extend(check.run(target))
            except Exception as exc:  # Checks should fail closed so one probe does not kill the scan.
                report.errors.append(
                    ScanError(target=target.display, check_id=check.id, message=str(exc))
                )

    report.finish()
    return report
