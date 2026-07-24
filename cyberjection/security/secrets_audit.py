"""Scans this project's *own* files for accidentally-committed credentials.

Not to be confused with `cyberjection.evaluators.regex.RegexEvaluator`
(Tier 1), which scans a *target's response text* during an evaluation run
for secrets the target leaked. This module scans the repository's own
source tree and campaign configuration files -- a maintainer-facing audit
tool, not an evaluation-pipeline component. The two intentionally don't
share a pattern list: a credential shape worth flagging in a committed
`.env` file (e.g. a bare, unprefixed 40-character token) would be far too
noisy to run against every LLM response Tier 1 evaluates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Pattern, Tuple

Severity = str  # "high" | "medium"

DEFAULT_EXCLUDED_DIRS = frozenset({".git", "__pycache__", "node_modules", ".venv", "venv", ".mypy_cache"})

# (pattern_name, compiled regex, severity). Ordered roughly by how
# unambiguous a match is -- structural patterns (key formats with a fixed
# prefix/length) are "high" since a match is very unlikely to be a false
# positive; the generic assignment pattern is "medium" since it also
# matches placeholder values like `api_key: "your-key-here"`.
_SECRET_PATTERNS: List[Tuple[str, Pattern[str], Severity]] = [
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}"), "high"),
    (
        "aws_secret_access_key",
        re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"),
        "high",
    ),
    ("private_key_header", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "high"),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), "high"),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "high"),
    (
        "generic_api_key_assignment",
        re.compile(r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token)\b\s*[=:]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
        "medium",
    ),
]

# Values that look like a hardcoded secret by shape but are conventionally
# used as placeholders in example/template files -- skipped so scanning
# examples/quickstart.yaml and .env.example doesn't flag its own
# intentionally-fake sample values.
_PLACEHOLDER_MARKERS = ("your-", "changeme", "example", "placeholder", "xxxxxxxx", "<", "${")


@dataclass(frozen=True)
class SecretFinding:
    source: str
    line: int
    pattern_name: str
    severity: Severity
    excerpt: str  # redacted -- never the raw matched secret


def _redact(matched_text: str) -> str:
    if len(matched_text) <= 8:
        return "*" * len(matched_text)
    return matched_text[:4] + "..." + f"[{len(matched_text)} chars redacted]"


def _looks_like_placeholder(line: str) -> bool:
    lowered = line.lower()
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


def scan_text_for_secrets(text: str, *, source_label: str) -> List[SecretFinding]:
    """Pure function: scans `text` line by line against every registered
    pattern. No filesystem access, so this is the function unit tests
    exercise directly with adversarial and benign strings."""

    findings: List[SecretFinding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if _looks_like_placeholder(line):
            continue
        for pattern_name, pattern, severity in _SECRET_PATTERNS:
            match = pattern.search(line)
            if match:
                findings.append(
                    SecretFinding(
                        source=source_label,
                        line=line_number,
                        pattern_name=pattern_name,
                        severity=severity,
                        excerpt=_redact(match.group(0)),
                    )
                )
    return findings


def scan_paths_for_secrets(
    paths: Iterable["Path | str"], *, excluded_dirs: Iterable[str] = DEFAULT_EXCLUDED_DIRS
) -> List[SecretFinding]:
    """Walks every file under each path in `paths` (files are scanned
    directly; directories are walked recursively, skipping `excluded_dirs`
    at any depth) and returns every `SecretFinding` across all of them.

    Files that can't be decoded as UTF-8 text (binaries, images, compiled
    artifacts) are skipped rather than raising -- a secret scanner's job
    is to flag committed *text* credentials, and a `.pyc` file failing to
    decode isn't a finding, it's just not a text file.
    """

    excluded = frozenset(excluded_dirs)
    findings: List[SecretFinding] = []

    for root in paths:
        root_path = Path(root)
        candidates = [root_path] if root_path.is_file() else sorted(root_path.rglob("*"))
        for candidate in candidates:
            if not candidate.is_file():
                continue
            if any(part in excluded for part in candidate.parts):
                continue
            try:
                text = candidate.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            findings.extend(scan_text_for_secrets(text, source_label=str(candidate)))

    return findings


# Config fields whose value should always be an env-var interpolation
# (`${VAR}` / `${VAR:-default}`), never a literal, in a version-controlled
# campaign YAML file -- currently just `api_key` (the one `SecretStr`
# field on `TargetConfig`), kept as an explicit list rather than
# reflecting over the schema so a future secret-shaped field must be
# deliberately added here rather than silently inheriting this check.
_SECRET_YAML_FIELDS = ("api_key",)
_YAML_FIELD_PATTERN = re.compile(
    r"^(?P<indent>\s*)(?P<field>" + "|".join(_SECRET_YAML_FIELDS) + r")\s*:\s*(?P<value>.+?)\s*$"
)


def scan_campaign_config_for_hardcoded_secrets(raw_yaml_text: str, *, source_label: str = "<config>") -> List[SecretFinding]:
    """Flags campaign YAML lines that assign a literal value to a
    known-sensitive field (`api_key`) instead of an environment-variable
    interpolation token.

    This runs on the *raw* YAML text before `cyberjection.config.loader`
    expands `${VAR}` tokens -- expansion happens first in the normal load
    path specifically so a literal value never needs to be written to
    begin with; this scanner is what catches it if one was anyway.
    """

    findings: List[SecretFinding] = []
    for line_number, line in enumerate(raw_yaml_text.splitlines(), start=1):
        match = _YAML_FIELD_PATTERN.match(line)
        if not match:
            continue
        value = match.group("value").strip("\"'")
        if value.startswith("${") or not value:
            continue  # properly interpolated, or an empty/null value -- nothing to flag
        findings.append(
            SecretFinding(
                source=source_label,
                line=line_number,
                pattern_name=f"hardcoded_{match.group('field')}",
                severity="high",
                excerpt=_redact(value),
            )
        )
    return findings
