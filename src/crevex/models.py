from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class ScanTarget:
    raw: str
    kind: str
    host: str
    scheme: str | None = None
    port: int | None = None
    path: str | None = None

    @property
    def display(self) -> str:
        if self.scheme:
            suffix = self.path or ""
            port = f":{self.port}" if self.port else ""
            return f"{self.scheme}://{self.host}{port}{suffix}"
        return self.raw


@dataclass
class Finding:
    id: str
    check_id: str
    title: str
    severity: str
    confidence: str
    target: str
    evidence: str
    impact: str
    recommendation: str
    references: list[str] = field(default_factory=list)
    location: str | None = None

    def sort_key(self) -> tuple[int, str, str]:
        return (-SEVERITY_ORDER.get(self.severity, 0), self.target, self.title)


@dataclass
class ScanError:
    target: str
    check_id: str
    message: str


@dataclass
class ScanReport:
    scanner: str
    version: str
    started_at: str
    finished_at: str | None = None
    profile: str = "standard"
    scan_type: str = "scan"
    targets: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)

    @classmethod
    def start(cls, version: str, scan_type: str, profile: str = "standard") -> "ScanReport":
        return cls(
            scanner="crevex",
            version=version,
            scan_type=scan_type,
            profile=profile,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

    def finish(self) -> None:
        self.finished_at = datetime.now(timezone.utc).isoformat()
        self.findings.sort(key=lambda item: item.sort_key())

    def duration_seconds(self) -> float | None:
        if not self.finished_at:
            return None
        started = datetime.fromisoformat(self.started_at)
        finished = datetime.fromisoformat(self.finished_at)
        return max((finished - started).total_seconds(), 0.0)

    def summary(self) -> dict[str, int]:
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["summary"] = self.summary()
        data["duration_seconds"] = self.duration_seconds()
        return data
