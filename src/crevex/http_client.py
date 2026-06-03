from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
from http.client import BadStatusLine, HTTPConnection, HTTPException, HTTPSConnection, RemoteDisconnected
from urllib.parse import urljoin, urlparse


class HttpProtocolError(ConnectionError):
    """Raised when a target does not speak the expected HTTP protocol."""


@dataclass
class HttpResponse:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes


def fetch(url: str, method: str = "GET", timeout: float = 10, max_body: int = 4096) -> HttpResponse:
    parsed = urlparse(url)
    if parsed.scheme == "https":
        connection = HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=timeout)
    elif parsed.scheme == "http":
        connection = HTTPConnection(parsed.hostname, parsed.port or 80, timeout=timeout)
    else:
        raise ValueError(f"unsupported URL scheme: {parsed.scheme}")

    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    try:
        connection.request(method, path, headers={"User-Agent": "crevex/0.1 safe-scanner"})
        response = connection.getresponse()
        body = response.read(max_body)
        headers = {key.lower(): value for key, value in response.getheaders()}
        return HttpResponse(url=url, status=response.status, headers=headers, body=body)
    except BadStatusLine as exc:
        raise HttpProtocolError(
            "target did not return a valid HTTP response; the port may belong to a non-HTTP service"
        ) from exc
    except RemoteDisconnected as exc:
        raise HttpProtocolError("target closed the connection before sending an HTTP response") from exc
    except ssl.SSLError as exc:
        raise HttpProtocolError("TLS handshake failed; the target may not speak HTTPS on this port") from exc
    except HTTPException as exc:
        raise HttpProtocolError(f"HTTP protocol error: {exc}") from exc
    finally:
        connection.close()


def probe_http_service(url: str, timeout: float = 3) -> tuple[bool, str | None]:
    try:
        fetch(url, method="HEAD", timeout=timeout, max_body=0)
    except HttpProtocolError as exc:
        return False, str(exc)
    except OSError as exc:
        return False, str(exc)
    return True, None


def absolute_url(base: str, path: str) -> str:
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def probe_tls_certificate(host: str, port: int = 443, timeout: float = 10) -> dict[str, object]:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            certificate = tls_sock.getpeercert()
            not_after = certificate.get("notAfter")
            expires_at = parsedate_to_datetime(not_after) if not_after else None
            return {
                "subject": certificate.get("subject"),
                "issuer": certificate.get("issuer"),
                "not_after": not_after,
                "expires_at": expires_at,
                "version": tls_sock.version(),
                "cipher": tls_sock.cipher(),
            }


def days_until(value: datetime) -> int:
    delta = value.replace(tzinfo=None) - datetime.utcnow()
    return delta.days
