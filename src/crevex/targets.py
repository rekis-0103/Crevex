from __future__ import annotations

import ipaddress
from pathlib import Path
from urllib.parse import urlparse

from .models import ScanTarget


def parse_target(raw: str) -> ScanTarget:
    value = raw.strip()
    if not value:
        raise ValueError("empty target")

    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return ScanTarget(
            raw=value,
            kind="web",
            host=parsed.hostname or parsed.netloc,
            scheme=parsed.scheme,
            port=parsed.port,
            path=parsed.path or "/",
        )

    try:
        ipaddress.ip_address(value)
        return ScanTarget(raw=value, kind="host", host=value)
    except ValueError:
        pass

    if "/" in value or "\\" in value:
        raise ValueError(f"unsupported target format: {raw}")

    return ScanTarget(raw=value, kind="host", host=value)


def load_targets(targets: list[str], target_file: str | None = None) -> list[ScanTarget]:
    values = list(targets)
    if target_file:
        path = Path(target_file)
        values.extend(
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        )

    if not values:
        raise ValueError("at least one target is required")

    return [parse_target(value) for value in values]
