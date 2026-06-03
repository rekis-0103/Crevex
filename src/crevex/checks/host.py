from __future__ import annotations

import socket
from typing import Iterable

from crevex.models import Finding, ScanTarget

from .base import BaseCheck


class DnsResolutionCheck(BaseCheck):
    id = "host.dns_resolution"
    name = "DNS resolution"
    target_kinds = {"host", "web"}

    def run(self, target: ScanTarget) -> Iterable[Finding]:
        try:
            addresses = sorted({item[4][0] for item in socket.getaddrinfo(target.host, None)})
        except socket.gaierror:
            return [
                Finding(
                    id=f"{self.id}.failed",
                    check_id=self.id,
                    title="DNS resolution failed",
                    severity="low",
                    confidence="high",
                    target=target.display,
                    evidence=f"Could not resolve {target.host}.",
                    impact="The target may be unreachable or incorrectly configured.",
                    recommendation="Verify DNS records and target spelling before scanning again.",
                )
            ]

        return [
            Finding(
                id=f"{self.id}.resolved",
                check_id=self.id,
                title="DNS resolution summary",
                severity="info",
                confidence="high",
                target=target.display,
                evidence=f"{target.host} resolves to {', '.join(addresses[:5])}.",
                impact="Informational inventory data for the scanned target.",
                recommendation="Review whether all resolved addresses are expected.",
            )
        ]


class TcpPortCheck(BaseCheck):
    id = "host.tcp_ports"
    name = "TCP port exposure"
    target_kinds = {"host", "web"}

    DEFAULT_PORTS = [21, 22, 25, 80, 443, 3306, 5432, 6379, 8080, 8443]

    RISKY_PORTS = {
        21: "FTP is exposed. Prefer SFTP/SSH and restrict access.",
        3306: "MySQL is exposed. Restrict database access to trusted networks only.",
        5432: "PostgreSQL is exposed. Restrict database access to trusted networks only.",
        6379: "Redis is exposed. Bind to private interfaces and require authentication where appropriate.",
    }

    def run(self, target: ScanTarget) -> Iterable[Finding]:
        findings: list[Finding] = []
        for port in self.DEFAULT_PORTS:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.0)
                try:
                    connected = sock.connect_ex((target.host, port)) == 0
                except OSError:
                    connected = False
            if connected:
                risky = port in self.RISKY_PORTS
                findings.append(
                    Finding(
                        id=f"{self.id}.{port}.open",
                        check_id=self.id,
                        title=f"Open TCP port: {port}",
                        severity="medium" if risky else "info",
                        confidence="high",
                        target=target.display,
                        evidence=f"TCP connection to {target.host}:{port} succeeded.",
                        impact="Publicly reachable services increase attack surface.",
                        recommendation=self.RISKY_PORTS.get(port, "Confirm that this service is expected to be reachable."),
                    )
                )
        return findings
