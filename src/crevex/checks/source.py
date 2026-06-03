from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from crevex.models import Finding, ScanTarget

from .base import BaseCheck


TEXT_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".py", ".php", ".env", ".ini", ".json", ".yml", ".yaml"}


def iter_source_files(root: Path) -> Iterable[Path]:
    ignored = {
        ".git",
        "node_modules",
        "vendor",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
        "test",
        "tests",
    }
    for path in root.rglob("*"):
        if any(part in ignored for part in path.parts):
            continue
        if path.is_file() and (path.suffix.lower() in TEXT_EXTENSIONS or path.name in {"requirements.txt", "package.json", "composer.json"}):
            yield path


class DependencyManifestCheck(BaseCheck):
    id = "code.dependency_manifests"
    name = "Dependency manifests"
    target_kinds = {"code"}

    MANIFESTS = {"package.json", "requirements.txt", "composer.json"}

    def run(self, target: ScanTarget) -> Iterable[Finding]:
        root = Path(target.raw)
        findings: list[Finding] = []
        for manifest in self.MANIFESTS:
            matches = list(root.rglob(manifest)) if root.exists() else []
            for path in matches:
                findings.append(
                    Finding(
                        id=f"{self.id}.{manifest}",
                        check_id=self.id,
                        title=f"Dependency manifest found: {manifest}",
                        severity="info",
                        confidence="high",
                        target=target.display,
                        location=str(path),
                        evidence=f"Found {path}.",
                        impact="Dependencies should be checked for known vulnerable versions.",
                        recommendation="Run dependency auditing in CI and upgrade vulnerable packages promptly.",
                    )
                )
        return findings


class SecretPatternCheck(BaseCheck):
    id = "code.secret_patterns"
    name = "Secret leakage patterns"
    target_kinds = {"code"}

    PATTERNS = [
        re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{12,}['\"]"),
        re.compile(r"AKIA[0-9A-Z]{16}"),
    ]

    def run(self, target: ScanTarget) -> Iterable[Finding]:
        root = Path(target.raw)
        findings: list[Finding] = []
        for path in iter_source_files(root):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for index, line in enumerate(text.splitlines(), start=1):
                if any(pattern.search(line) for pattern in self.PATTERNS):
                    findings.append(
                        Finding(
                            id=f"{self.id}.possible_secret",
                            check_id=self.id,
                            title="Possible hardcoded secret",
                            severity="high",
                            confidence="medium",
                            target=target.display,
                            location=f"{path}:{index}",
                            evidence="Line matches a common secret/token pattern.",
                            impact="Hardcoded secrets can be reused by attackers if source code leaks.",
                            recommendation="Revoke the exposed secret, create a new value, and load it from environment or a secret manager.",
                        )
                    )
        return findings


class SourceRiskPatternCheck(BaseCheck):
    id = "code.risk_patterns"
    name = "Source-code risk patterns"
    target_kinds = {"code"}

    RULES = [
        (
            "Potential SQL injection pattern",
            re.compile(r"(?i)(select|insert|update|delete).*(\+|%|\{.*\}|f['\"]|`.*\$\{)"),
            "medium",
            "Use parameterized queries or prepared statements instead of string-building SQL.",
        ),
        (
            "Debug mode appears enabled",
            re.compile(r"(?i)(debug\s*=\s*true|app\.debug\s*=\s*true)"),
            "medium",
            "Disable debug mode outside local development.",
        ),
        (
            "Potential unsafe redirect",
            re.compile(r"(?i)(redirect|location\.href|header\(['\"]location:).*(request|params|query|\$_GET)"),
            "medium",
            "Validate redirect destinations against an allowlist.",
        ),
        (
            "Potential command execution from input",
            re.compile(r"(?i)\b(exec|shell_exec|subprocess|os\.system)\b.*(request|params|input|\$_GET|\$_POST)"),
            "high",
            "Avoid passing user input to shell commands; use safe APIs and strict allowlists.",
        ),
    ]

    def run(self, target: ScanTarget) -> Iterable[Finding]:
        root = Path(target.raw)
        findings: list[Finding] = []
        for path in iter_source_files(root):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for index, line in enumerate(text.splitlines(), start=1):
                if "re.compile(" in line:
                    continue
                for title, pattern, severity, recommendation in self.RULES:
                    if pattern.search(line):
                        findings.append(
                            Finding(
                                id=f"{self.id}.{title.lower().replace(' ', '_')}",
                                check_id=self.id,
                                title=title,
                                severity=severity,
                                confidence="low",
                                target=target.display,
                                location=f"{path}:{index}",
                                evidence="Line matches a risky source-code pattern.",
                                impact="This pattern may become exploitable depending on input validation and surrounding code.",
                                recommendation=recommendation,
                            )
                        )
        return findings
