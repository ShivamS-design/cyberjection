"""Credential and internal-endpoint leak detection for model repositories.

Model repositories leak secrets in predictable places: a model card's
"how to use" snippet with a real `hf_...` token pasted in, a
`config.json` or training YAML carrying a database URL or W&B key, a
notebook export with an OpenAI key, a Slack webhook from a training
callback. And because a Hub repository is a Git repository, a secret
"removed" in a later commit is still served from the earlier one --
`HubGuardClient` therefore also scans commit messages and earlier
revisions of text files (see `history_depth`).

This is distinct from both existing secret scanners:
`cyberjection.security.secrets_audit` scans *this project's own* source
tree, and the Tier 1 `RegexEvaluator` scans *a target's responses*. This
one scans *third-party artifacts*, so it carries patterns those don't need
(Hugging Face, Replicate and W&B tokens, DB connection strings, webhook
and internal URLs) and judges placeholders by the matched *value* rather
than the whole line -- a README line that says "for example" can still
contain a live key.

Excerpts are always redacted; the raw secret never leaves this module.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import List, Optional, Pattern, Tuple

from cyberjection.hubguard.models import FindingCategory, HubFinding, Severity

TEXT_EXTENSIONS = frozenset(
    {".md", ".txt", ".json", ".yaml", ".yml", ".py", ".cfg", ".ini", ".toml", ".sh", ".env", ".ipynb", ".js", ".ts", ".rst", ".csv", ".jsonl", ".xml", ".html"}
)
TEXT_FILENAMES = frozenset({".env", "dockerfile", "makefile", ".gitattributes", "license", "readme"})
MAX_TEXT_FILE_BYTES = 2 << 20

# (rule, pattern, severity, group-index-of-the-secret-value)
_PATTERNS: List[Tuple[str, Pattern[str], Severity, int]] = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"), Severity.CRITICAL, 0),
    ("huggingface_token", re.compile(r"\b(hf_[A-Za-z0-9]{34,40})\b"), Severity.HIGH, 1),
    ("huggingface_org_token", re.compile(r"\b(api_org_[A-Za-z0-9]{34})\b"), Severity.HIGH, 1),
    ("anthropic_api_key", re.compile(r"\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,})"), Severity.HIGH, 1),
    ("openai_api_key", re.compile(r"\b(sk-(?:proj-|svcacct-|admin-)?(?!ant-)[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}|sk-(?:proj-|svcacct-)[A-Za-z0-9_\-]{40,}|sk-[A-Za-z0-9]{48})\b"), Severity.HIGH, 1),
    ("aws_access_key_id", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), Severity.HIGH, 1),
    ("aws_secret_access_key", re.compile(r"(?i)aws_secret_access_key[\"']?\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})"), Severity.HIGH, 1),
    ("google_api_key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), Severity.HIGH, 1),
    ("github_token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"), Severity.HIGH, 1),
    ("gitlab_token", re.compile(r"\b(glpat-[A-Za-z0-9_\-]{20,})\b"), Severity.HIGH, 1),
    ("slack_token", re.compile(r"\b(xox[abposr]-[0-9A-Za-z\-]{10,})\b"), Severity.HIGH, 1),
    ("stripe_live_key", re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{24,})\b"), Severity.HIGH, 1),
    ("sendgrid_api_key", re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"), Severity.HIGH, 1),
    ("replicate_token", re.compile(r"\b(r8_[A-Za-z0-9]{37})\b"), Severity.HIGH, 1),
    ("wandb_api_key", re.compile(r"(?i)wandb[_-]?api[_-]?key[\"']?\s*[=:]\s*[\"']?([0-9a-f]{40})\b"), Severity.HIGH, 1),
    ("azure_storage_key", re.compile(r"AccountKey=([A-Za-z0-9+/=]{80,})"), Severity.HIGH, 1),
    (
        "database_url",
        re.compile(r"\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|clickhouse)://[^\s:/@\"']+:([^\s@\"']+)@[^\s\"'<>]+)"),
        Severity.HIGH,
        2,
    ),
    ("slack_webhook", re.compile(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)"), Severity.HIGH, 1),
    ("discord_webhook", re.compile(r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+)"), Severity.HIGH, 1),
    ("teams_webhook", re.compile(r"(https://[a-z0-9\-]+\.webhook\.office\.com/webhookb2/[^\s\"'<>]+)"), Severity.HIGH, 1),
    ("jwt", re.compile(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"), Severity.MEDIUM, 1),
    ("generic_webhook", re.compile(r"(https?://[^\s\"'<>]*/(?:webhooks?|hooks)/[A-Za-z0-9_\-/]{16,})"), Severity.MEDIUM, 1),
    (
        "generic_secret_assignment",
        re.compile(r"(?i)[\"']?\b([a-z0-9_]*(?:api[_-]?key|secret|token|passw(?:or)?d|access[_-]?key)[a-z0-9_]*)\b[\"']?\s*[=:]\s*[\"']([^\"'\s]{16,})[\"']"),
        Severity.MEDIUM,
        2,
    ),
    (
        "internal_url",
        re.compile(
            r"(https?://(?:[a-z0-9\-]+\.)+(?:internal|corp|intranet|lan|local)(?::\d+)?[^\s\"'<>]*"
            r"|https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?::\d+)?[^\s\"'<>]*)",
            re.IGNORECASE,
        ),
        Severity.LOW,
        1,
    ),
]

_PLACEHOLDER_MARKERS = (
    "xxxx",
    "your_",
    "your-",
    "yourtoken",
    "<",
    ">",
    "${",
    "{{",
    "example",
    "placeholder",
    "changeme",
    "change_me",
    "dummy",
    "redacted",
    "****",
    "...",
    "insert",
    "replace",
    "hf_token",
    "token_here",
    "_here",
    "none",
    "null",
    "password",
)


@dataclass(frozen=True)
class SecretMatch:
    rule: str
    severity: Severity
    line: int
    redacted: str


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...[{len(value)} chars redacted]"


def _entropy(value: str) -> float:
    counts = Counter(value)
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values()) if total else 0.0


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
        return True
    return len(set(lowered)) <= 3


def find_secrets(text: str) -> List[SecretMatch]:
    """Pure function: every credential-shaped match in `text`."""

    matches: List[SecretMatch] = []
    claimed: List[Tuple[int, int]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if len(line) > 20_000:
            line = line[:20_000]
        claimed.clear()
        for rule, pattern, severity, group in _PATTERNS:
            for match in pattern.finditer(line):
                span = match.span()
                if any(span[0] < end and start < span[1] for start, end in claimed):
                    continue  # a more specific rule already reported this text
                value = match.group(group) or match.group(0)
                if rule != "private_key" and _is_placeholder(value):
                    continue
                if rule == "generic_secret_assignment" and _entropy(value) < 3.3:
                    continue
                if rule == "internal_url" and _is_placeholder(match.group(0)):
                    continue
                claimed.append(span)
                matches.append(SecretMatch(rule, severity, line_number, _redact(value)))
    return matches


def scan_text_for_leaks(text: str, *, source: str, context: Optional[str] = None) -> List[HubFinding]:
    findings: List[HubFinding] = []
    for match in find_secrets(text):
        where = f" ({context})" if context else ""
        findings.append(
            HubFinding(
                rule_id=f"secrets.{match.rule}",
                category=FindingCategory.SECRETS,
                severity=match.severity,
                description=(
                    f"Possible {match.rule.replace('_', ' ')} in `{source}`{where}."
                    if match.rule != "internal_url"
                    else f"Internal/private network endpoint disclosed in `{source}`{where}."
                ),
                file=source,
                line=match.line,
                evidence=match.redacted,
                remediation=(
                    "Treat the credential as compromised: revoke and rotate it. Removing it in a new "
                    "commit does not remove it from repository history."
                    if match.rule != "internal_url"
                    else "Confirm the endpoint is not sensitive infrastructure."
                ),
            )
        )
    return findings


def is_text_candidate(path: str, size: Optional[int] = None) -> bool:
    if size is not None and size > MAX_TEXT_FILE_BYTES:
        return False
    pure = PurePosixPath(path)
    return pure.suffix.lower() in TEXT_EXTENSIONS or pure.name.lower() in TEXT_FILENAMES or pure.name.lower().startswith(".env")
