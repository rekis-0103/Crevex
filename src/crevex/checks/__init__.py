from .base import BaseCheck
from .host import DnsResolutionCheck, TcpPortCheck
from .source import DependencyManifestCheck, SecretPatternCheck, SourceRiskPatternCheck
from .web import HttpSecurityHeadersCheck, SensitivePathCheck, TlsCertificateCheck


DEFAULT_DAST_CHECKS: list[type[BaseCheck]] = [
    DnsResolutionCheck,
    TcpPortCheck,
    HttpSecurityHeadersCheck,
    SensitivePathCheck,
    TlsCertificateCheck,
]

DEFAULT_CODE_CHECKS: list[type[BaseCheck]] = [
    DependencyManifestCheck,
    SecretPatternCheck,
    SourceRiskPatternCheck,
]


def build_checks(
    scan_type: str,
    include: set[str] | None = None,
    exclude: set[str] | None = None,
) -> list[BaseCheck]:
    classes: list[type[BaseCheck]] = []
    if scan_type in {"scan", "audit"}:
        classes.extend(DEFAULT_DAST_CHECKS)
    if scan_type in {"code-scan", "audit"}:
        classes.extend(DEFAULT_CODE_CHECKS)

    checks = [check_class() for check_class in classes]
    if include:
        checks = [check for check in checks if check.id in include]
    if exclude:
        checks = [check for check in checks if check.id not in exclude]
    return checks


def list_checks() -> list[BaseCheck]:
    return build_checks("audit")
