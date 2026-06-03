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

    PORTS_BY_PROFILE = {
        "quick": [80, 443],
        "standard": [21, 22, 25, 80, 443, 3306, 5432, 6379, 8080, 8443],
        "deep": [
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            143,
            389,
            443,
            445,
            587,
            993,
            995,
            1433,
            1521,
            3306,
            5432,
            6379,
            8000,
            8080,
            8081,
            8443,
            9000,
            9200,
            11211,
            27017,
        ],
    }

    RISKY_PORTS = {
        21: "FTP is exposed. Prefer SFTP/SSH and restrict access.",
        3306: "MySQL is exposed. Restrict database access to trusted networks only.",
        5432: "PostgreSQL is exposed. Restrict database access to trusted networks only.",
        6379: "Redis is exposed. Bind to private interfaces and require authentication where appropriate.",
    }

    def ports_for_target(self, target: ScanTarget) -> list[int]:
        ports = list(self.PORTS_BY_PROFILE.get(self.profile, self.PORTS_BY_PROFILE["standard"]))
        if target.port and target.port not in ports:
            ports.append(target.port)
        return sorted(ports)

    def run(self, target: ScanTarget) -> Iterable[Finding]:
        findings: list[Finding] = []
        for port in self.ports_for_target(target):
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
