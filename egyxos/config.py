"""Small TOML-backed configuration layer (stdlib only on Python 3.11+)."""

import os
import sys
from pathlib import Path
from typing import Any, Dict

from .errors import ConfigurationError

DEFAULTS: Dict[str, Any] = {
    "timeout": 120,
    "output_dir": "egyxos-results",
    "allow_private": False,
    "tools": {},
}


def config_path() -> Path:
    override = os.environ.get("EGYXOS_CONFIG")
    if override:
        return Path(override).expanduser()
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "egyxos" / "config.toml"


def load_config(path: Path = None) -> Dict[str, Any]:
    result = dict(DEFAULTS)
    path = Path(path or config_path()).expanduser()
    if not path.exists():
        return result
    try:
        if sys.version_info >= (3, 11):
            import tomllib
            with path.open("rb") as handle:
                data = tomllib.load(handle)
        else:  # pragma: no cover - only used on Python 3.9/3.10
            data = _minimal_toml(path)
    except (OSError, ValueError) as exc:
        raise ConfigurationError("Could not read configuration.", details={"path": str(path), "reason": str(exc)})
    result.update(data)
    return result


def write_default_config(path: Path = None) -> Path:
    path = Path(path or config_path()).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "# Egyxos configuration\n"
        "timeout = 120\n"
        'output_dir = "egyxos-results"\n'
        "allow_private = false\n",
        encoding="utf-8",
    )
    return path


def _minimal_toml(path: Path) -> Dict[str, Any]:
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        if value.lower() in ("true", "false"):
            result[key] = value.lower() == "true"
        elif value.startswith('"') and value.endswith('"'):
            result[key] = value[1:-1]
        else:
            try:
                result[key] = int(value)
            except ValueError:
                result[key] = value
    return result
