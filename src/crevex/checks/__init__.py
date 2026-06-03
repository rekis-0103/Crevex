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

DAST_CHECKS_BY_PROFILE: dict[str, list[type[BaseCheck]]] = {
    "quick": [
        DnsResolutionCheck,
        TcpPortCheck,
        HttpSecurityHeadersCheck,
    ],
    "standard": DEFAULT_DAST_CHECKS,
    "deep": DEFAULT_DAST_CHECKS,
}

CODE_CHECKS_BY_PROFILE: dict[str, list[type[BaseCheck]]] = {
    "quick": [
        DependencyManifestCheck,
        SecretPatternCheck,
    ],
    "standard": DEFAULT_CODE_CHECKS,
    "deep": DEFAULT_CODE_CHECKS,
}


def build_checks(
    scan_type: str,
    profile: str = "standard",
    include: set[str] | None = None,
    exclude: set[str] | None = None,
) -> list[BaseCheck]:
    classes: list[type[BaseCheck]] = []
    if scan_type in {"scan", "audit"}:
        classes.extend(DAST_CHECKS_BY_PROFILE.get(profile, DEFAULT_DAST_CHECKS))
    if scan_type in {"code-scan", "audit"}:
        classes.extend(CODE_CHECKS_BY_PROFILE.get(profile, DEFAULT_CODE_CHECKS))

    checks = [check_class(profile=profile) for check_class in classes]
    if include:
        checks = [check for check in checks if check.id in include]
    if exclude:
        checks = [check for check in checks if check.id not in exclude]
    return checks


def list_checks() -> list[BaseCheck]:
    return build_checks("audit", profile="deep")
