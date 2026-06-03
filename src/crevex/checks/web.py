from __future__ import annotations

from typing import Iterable

from crevex.http_client import absolute_url, days_until, fetch, probe_tls_certificate
from crevex.models import Finding, ScanTarget

from .base import BaseCheck


class HttpSecurityHeadersCheck(BaseCheck):
    id = "web.security_headers"
    name = "HTTP security headers"
    target_kinds = {"web"}

    HEADERS = {
        "strict-transport-security": ("medium", "Enable HSTS so browsers require HTTPS for this host."),
        "content-security-policy": ("medium", "Add a Content-Security-Policy to reduce XSS impact."),
        "x-frame-options": ("low", "Add X-Frame-Options or frame-ancestors to reduce clickjacking risk."),
        "x-content-type-options": ("low", "Set X-Content-Type-Options: nosniff."),
        "referrer-policy": ("low", "Set a Referrer-Policy appropriate for the application."),
    }

    def run(self, target: ScanTarget) -> Iterable[Finding]:
        if target.kind != "web":
            return []
        response = fetch(target.display, method="GET")
        findings: list[Finding] = []

        for header, (severity, recommendation) in self.HEADERS.items():
            if header not in response.headers:
                findings.append(
                    Finding(
                        id=f"{self.id}.{header}.missing",
                        check_id=self.id,
                        title=f"Missing security header: {header}",
                        severity=severity,
                        confidence="high",
                        target=target.display,
                        evidence=f"HTTP {response.status} response did not include {header}.",
                        impact="Browsers lose a defense-in-depth control for common web attacks.",
                        recommendation=recommendation,
                        references=["https://owasp.org/www-project-secure-headers/"],
                    )
                )

        set_cookie = response.headers.get("set-cookie", "")
        if set_cookie:
            lower_cookie = set_cookie.lower()
            for flag, rec in {
                "httponly": "Set HttpOnly on session cookies to reduce script access.",
                "secure": "Set Secure on cookies that should only be sent over HTTPS.",
                "samesite": "Set SameSite=Lax or Strict unless cross-site use is required.",
            }.items():
                if flag not in lower_cookie:
                    findings.append(
                        Finding(
                            id=f"{self.id}.cookie.{flag}.missing",
                            check_id=self.id,
                            title=f"Cookie missing {flag} flag",
                            severity="medium" if flag != "samesite" else "low",
                            confidence="medium",
                            target=target.display,
                            evidence=f"Set-Cookie header lacks {flag}.",
                            impact="Cookie exposure or cross-site request risk may increase.",
                            recommendation=rec,
                            references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                        )
                    )
        return findings


class SensitivePathCheck(BaseCheck):
    id = "web.sensitive_paths"
    name = "Sensitive exposed paths"
    target_kinds = {"web"}

    PATHS = [".env", "config.php", "backup.zip", "db.sql", ".git/HEAD"]

    def run(self, target: ScanTarget) -> Iterable[Finding]:
        if target.kind != "web":
            return []

        findings: list[Finding] = []
        for path in self.PATHS:
            url = absolute_url(target.display, path)
            response = fetch(url, method="GET", max_body=1024)
            if response.status in {200, 206} and response.body.strip():
                findings.append(
                    Finding(
                        id=f"{self.id}.{path}",
                        check_id=self.id,
                        title=f"Potential sensitive file exposed: {path}",
                        severity="high",
                        confidence="medium",
                        target=target.display,
                        location=url,
                        evidence=f"{url} returned HTTP {response.status} with a non-empty body.",
                        impact="Sensitive files can leak credentials, source metadata, or internal configuration.",
                        recommendation="Remove this file from the web root and restrict direct access with server rules.",
                        references=["https://owasp.org/www-project-top-ten/"],
                    )
                )
        return findings


class TlsCertificateCheck(BaseCheck):
    id = "web.tls_certificate"
    name = "TLS certificate"
    target_kinds = {"web"}

    def run(self, target: ScanTarget) -> Iterable[Finding]:
        if target.kind != "web" or target.scheme != "https":
            return []

        port = target.port or 443
        info = probe_tls_certificate(target.host, port=port)
        findings: list[Finding] = []
        expires_at = info.get("expires_at")
        if expires_at is not None:
            days = days_until(expires_at)
            if days < 30:
                findings.append(
                    Finding(
                        id=f"{self.id}.expires_soon",
                        check_id=self.id,
                        title="TLS certificate expires soon",
                        severity="medium" if days >= 0 else "high",
                        confidence="high",
                        target=target.display,
                        evidence=f"Certificate expires in {days} days.",
                        impact="Users may receive browser errors if the certificate expires.",
                        recommendation="Renew and deploy a valid certificate before expiration.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
                    )
                )
        return findings
