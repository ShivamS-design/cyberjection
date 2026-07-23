"""YAML campaign configuration loader with environment variable expansion.

Responsible for turning a `.yaml` file (or raw YAML string) on disk into a
validated :class:`~cyberjection.config.schema.CampaignConfig`. Two things
happen before Pydantic ever sees the data:

1. ``${VAR_NAME}`` and ``${VAR_NAME:-default}`` tokens anywhere in the raw
   YAML text are substituted with values from the process environment. This
   keeps secrets (API keys) out of version-controlled campaign files.
2. The YAML is parsed with ``yaml.safe_load`` into plain Python structures.

Any failure at either stage is normalized into a
:class:`~cyberjection.utils.exceptions.ConfigValidationError` so callers get
one predictable exception type regardless of whether the problem was a
missing environment variable, malformed YAML, or a Pydantic validation
failure.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, Optional, Union

import yaml
from pydantic import ValidationError

from cyberjection.config.schema import CampaignConfig
from cyberjection.utils.exceptions import ConfigValidationError

# Matches ${VAR_NAME} and ${VAR_NAME:-default_value}
_ENV_VAR_PATTERN = re.compile(r"\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)(:-(?P<default>[^}]*))?\}")


def expand_env_vars(raw_text: str, *, strict: bool = True, env: Optional[Dict[str, str]] = None) -> str:
    """Substitute ``${VAR}`` / ``${VAR:-default}`` tokens with environment values.

    Args:
        raw_text: Raw YAML (or any text) containing interpolation tokens.
        strict: If True, raise when a referenced variable has no environment
            value and no inline default. If False, unresolved tokens are
            replaced with an empty string.
        env: Optional explicit environment mapping (defaults to ``os.environ``);
            primarily useful for deterministic unit testing.

    Returns:
        The text with all recognized tokens substituted.

    Raises:
        ConfigValidationError: If ``strict`` is True and a variable is unset
            with no default provided.
    """

    environment = os.environ if env is None else env
    missing: list[str] = []

    def _replace(match: "re.Match[str]") -> str:
        name = match.group("name")
        default = match.group("default")
        if name in environment:
            return environment[name]
        if default is not None:
            return default
        if strict:
            missing.append(name)
            return ""
        return ""

    substituted = _ENV_VAR_PATTERN.sub(_replace, raw_text)

    if missing:
        unique_missing = sorted(set(missing))
        raise ConfigValidationError(
            "Missing required environment variable(s) referenced in configuration: "
            f"{', '.join(unique_missing)}. Set them in the environment or supply an "
            "inline default via ${VAR:-default}."
        )

    return substituted


def _parse_yaml(text: str, *, source: str) -> dict:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigValidationError(f"Failed to parse YAML from {source}: {exc}") from exc

    if data is None:
        raise ConfigValidationError(f"Configuration source '{source}' is empty.")
    if not isinstance(data, dict):
        raise ConfigValidationError(
            f"Configuration source '{source}' must be a YAML mapping at the top level, "
            f"got {type(data).__name__}."
        )
    return data


def load_config_from_string(raw_yaml: str, *, source: str = "<string>", strict_env: bool = True) -> CampaignConfig:
    """Parse and validate a `CampaignConfig` from a raw YAML string."""

    expanded = expand_env_vars(raw_yaml, strict=strict_env)
    data = _parse_yaml(expanded, source=source)
    try:
        return CampaignConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigValidationError(f"Configuration in {source} failed schema validation:\n{exc}") from exc


def load_config(path: Union[str, Path], *, strict_env: bool = True) -> CampaignConfig:
    """Load, expand, parse, and validate a campaign configuration file.

    Args:
        path: Path to a `.yaml` / `.yml` campaign configuration file.
        strict_env: Whether missing ``${VAR}`` tokens should raise (default)
            or silently resolve to an empty string.

    Returns:
        A fully validated :class:`CampaignConfig`.

    Raises:
        ConfigValidationError: On missing file, malformed YAML, unresolved
            required environment variables, or schema validation failure.
    """

    config_path = Path(path)
    if not config_path.exists():
        raise ConfigValidationError(f"Configuration file not found: {config_path}")
    if not config_path.is_file():
        raise ConfigValidationError(f"Configuration path is not a file: {config_path}")

    raw_yaml = config_path.read_text(encoding="utf-8")
    return load_config_from_string(raw_yaml, source=str(config_path), strict_env=strict_env)
