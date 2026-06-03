from __future__ import annotations

from pathlib import Path
from typing import Any


DEFAULT_CONFIG_FILE = "crevex.yml"

SUPPORTED_KEYS = {
    "profile",
    "format",
    "output",
    "targets_file",
    "code_path",
    "include_check",
    "exclude_check",
    "no_color",
    "no_spinner",
    "quiet",
    "verbose",
}


def parse_scalar(value: str) -> Any:
    stripped = value.strip()
    if not stripped:
        return ""
    if stripped.lower() in {"true", "yes", "on"}:
        return True
    if stripped.lower() in {"false", "no", "off"}:
        return False
    if stripped.startswith("[") and stripped.endswith("]"):
        inner = stripped[1:-1].strip()
        if not inner:
            return []
        return [parse_scalar(item.strip()) for item in inner.split(",")]
    if (
        (stripped.startswith('"') and stripped.endswith('"'))
        or (stripped.startswith("'") and stripped.endswith("'"))
    ):
        return stripped[1:-1]
    return stripped


def load_config(path: str | None = None) -> dict[str, Any]:
    config_path = Path(path or DEFAULT_CONFIG_FILE)
    if not config_path.exists():
        if path:
            raise ValueError(f"config file does not exist: {path}")
        return {}

    values: dict[str, Any] = {}
    current_list_key: str | None = None
    for line_number, raw_line in enumerate(config_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue

        stripped = line.strip()
        if stripped.startswith("- "):
            if not current_list_key:
                raise ValueError(f"list item without a key in {config_path}:{line_number}")
            values.setdefault(current_list_key, []).append(parse_scalar(stripped[2:]))
            continue

        if ":" not in stripped:
            raise ValueError(f"invalid config line in {config_path}:{line_number}")

        key, value = stripped.split(":", 1)
        key = key.strip().replace("-", "_")
        if key not in SUPPORTED_KEYS:
            raise ValueError(f"unsupported config key '{key}' in {config_path}:{line_number}")

        value = value.strip()
        if value:
            values[key] = parse_scalar(value)
            current_list_key = None
        else:
            values[key] = []
            current_list_key = key

    return values


def list_to_csv(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    return str(value)
