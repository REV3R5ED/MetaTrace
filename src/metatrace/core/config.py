"""JSON configuration with named profiles.

Resolution order (later wins):
  1. built-in defaults
  2. JSON config file (``--config PATH`` or ``~/.metatrace/config.json``)
  3. selected profile (``--profile NAME`` picks ``profiles.NAME``)
  4. explicit CLI flags

JSON is used instead of TOML so configuration works identically on
Python 3.10 through 3.13 (stdlib ``tomllib`` is 3.11+).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class ConfigError(Exception):
    """Raised when a configuration file is invalid."""


DEFAULTS: dict[str, Any] = {
    # Hash algorithms computed for every inspected file ("sha256" always
    # included; "sha512" optional because it doubles hashing cost).
    "hash_algorithms": ["sha256"],
    # Refuse files larger than this (forensic bound against decompression
    # bombs and runaway reads). 0 disables the check.
    "max_file_size_bytes": 512 * 1024 * 1024,
    # Defensive EXIF parser bounds.
    "exif_max_tags": 512,
    "exif_max_value_bytes": 1024 * 1024,
    # Bytes of file header read for format identification.
    "identify_header_bytes": 65536,
}

_PROFILE_DEFAULT = "default"


def default_config_path() -> Path:
    override = os.environ.get("METATRACE_CONFIG")
    if override:
        return Path(override)
    return Path.home() / ".metatrace" / "config.json"


def _checked_profile(raw: Any, where: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: profile must be a JSON object")
    unknown = sorted(set(raw) - set(DEFAULTS))
    if unknown:
        raise ConfigError(
            f"{where}: unknown setting(s) {', '.join(unknown)}; "
            f"expected only {', '.join(sorted(DEFAULTS))}"
        )
    values = dict(raw)
    algos = values.get("hash_algorithms", ["sha256"])
    if not isinstance(algos, list) or not algos:
        raise ConfigError(f"{where}: 'hash_algorithms' must be a non-empty list")
    for algo in algos:
        if algo not in ("sha256", "sha512"):
            raise ConfigError(
                f"{where}: unsupported hash algorithm {algo!r} "
                "(supported: 'sha256', 'sha512')"
            )
    return values


@dataclass
class AppConfig:
    """Effective configuration for one invocation."""

    values: dict[str, Any] = field(default_factory=lambda: dict(DEFAULTS))
    profile: str = _PROFILE_DEFAULT
    source: str = "defaults"

    def get(self, key: str) -> Any:
        return self.values[key]

    def __getitem__(self, key: str) -> Any:
        return self.values[key]

    def to_dict(self) -> dict[str, Any]:
        return {"profile": self.profile, "source": self.source, **self.values}


def load_config(
    path: str | Path | None = None,
    profile: str = _PROFILE_DEFAULT,
    overrides: dict[str, Any] | None = None,
) -> AppConfig:
    """Load configuration, applying the resolution order documented above."""
    values: dict[str, Any] = dict(DEFAULTS)
    source = "defaults"
    cfg_path = Path(path) if path else default_config_path()

    if cfg_path.exists():
        try:
            raw = json.loads(cfg_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"cannot read config file {cfg_path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ConfigError(f"config file {cfg_path} must contain a JSON object")
        if "profiles" not in raw:
            values.update(_checked_profile(raw, str(cfg_path)))
        else:
            profiles = raw["profiles"]
            if not isinstance(profiles, dict):
                raise ConfigError(
                    f"config file {cfg_path}: 'profiles' must be an object"
                )
            if profile not in profiles:
                available = sorted(profiles) or ["(none defined)"]
                raise ConfigError(
                    f"config file {cfg_path}: profile {profile!r} is not defined; "
                    f"available: {', '.join(available)}"
                )
            values.update(
                _checked_profile(profiles[profile], f"{cfg_path}: profile {profile!r}")
            )
        source = str(cfg_path)

    if overrides:
        unknown = sorted(set(overrides) - set(DEFAULTS))
        if unknown:
            raise ConfigError(f"unknown setting(s) {', '.join(unknown)}")
        values.update(overrides)

    return AppConfig(values=values, profile=profile, source=source)


def example_config() -> str:
    return json.dumps(
        {
            "profiles": {
                "default": dict(DEFAULTS),
                "thorough": {**DEFAULTS, "hash_algorithms": ["sha256", "sha512"]},
            }
        },
        indent=2,
    )
