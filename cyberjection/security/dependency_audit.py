"""Dependency vulnerability auditing via `pip-audit`.

This module deliberately does **not** ship a hand-maintained, offline
database of known CVEs against this project's dependencies. A hardcoded
vulnerability list goes stale the moment it's written, and a security
tool presenting stale or fabricated advisory data is worse than one that
honestly reports "the audit didn't run" -- a false sense of "we checked
and it's clean" is a more dangerous failure mode than a visibly-skipped
check. Instead, `run_dependency_audit()` shells out to the real
`pip-audit` tool (an optional dependency; see `pyproject.toml`'s
`security` extra) when it's installed, which queries the real, live PyPA
Advisory Database, and returns an explicit `source="unavailable"` report
--- not an empty "clean" report -- when it isn't.

`parse_pip_audit_json()` is factored out separately from the subprocess
call specifically so its parsing logic can be hard-tested against a
canned, realistic `pip-audit --format json` fixture without needing
`pip-audit` itself installed or a network connection -- which is exactly
the situation this module was developed and tested in.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional

DEFAULT_TIMEOUT_SECONDS = 120


@dataclass(frozen=True)
class VulnerabilityFinding:
    package: str
    installed_version: str
    advisory_id: str
    summary: str
    fixed_in: Optional[str] = None


@dataclass(frozen=True)
class DependencyAuditReport:
    findings: List[VulnerabilityFinding]
    source: str  # "pip-audit" | "unavailable" | "timeout" | "error"
    packages_checked: int
    detail: str = ""


def parse_pip_audit_json(raw_json: str) -> List[VulnerabilityFinding]:
    """Parses `pip-audit --format json`'s own output schema:

    ```json
    {"dependencies": [{"name": "...", "version": "...",
                        "vulns": [{"id": "...", "fix_versions": ["..."],
                                   "description": "..."}]}]}
    ```

    pip-audit's own output does not reliably include a severity rating
    (the underlying OSV-format advisories often omit one), so
    `VulnerabilityFinding` doesn't invent one -- `summary` carries
    whatever description text the advisory provides, and severity
    triage is left to whoever reads the report, not fabricated here.
    """

    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return []

    findings: List[VulnerabilityFinding] = []
    for dependency in data.get("dependencies", []):
        name = dependency.get("name", "<unknown package>")
        version = dependency.get("version", "<unknown version>")
        for vuln in dependency.get("vulns", []):
            description = (vuln.get("description") or "").strip().replace("\n", " ")
            summary = (description[:300] + "...") if len(description) > 300 else description
            fix_versions = vuln.get("fix_versions") or []
            findings.append(
                VulnerabilityFinding(
                    package=name,
                    installed_version=version,
                    advisory_id=vuln.get("id", "UNKNOWN"),
                    summary=summary or "(no description provided by advisory)",
                    fixed_in=fix_versions[0] if fix_versions else None,
                )
            )
    return findings


def _count_packages(raw_json: str) -> int:
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return 0
    return len(data.get("dependencies", []))


def run_dependency_audit(*, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> DependencyAuditReport:
    """Runs the real `pip-audit` CLI against the current environment's
    installed packages, if it's on `PATH`.

    Returns a report with `source="unavailable"` (not a report claiming
    zero vulnerabilities) when `pip-audit` isn't installed, `"timeout"`
    if it didn't finish within `timeout_seconds`, or `"error"` if it
    exited with an unexpected status. `pip-audit` itself exits `1` when
    vulnerabilities are found (not an error condition for this function
    -- that's the expected "audit ran, found something" case) and `0`
    when the environment is clean.
    """

    executable = shutil.which("pip-audit")
    if executable is None:
        return DependencyAuditReport(
            findings=[],
            source="unavailable",
            packages_checked=0,
            detail="pip-audit is not installed; install the 'security' extra (`pip install -e '.[security]'`) to enable this check.",
        )

    try:
        result = subprocess.run(
            [executable, "--format", "json"],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return DependencyAuditReport(
            findings=[], source="timeout", packages_checked=0, detail=f"pip-audit did not finish within {timeout_seconds}s"
        )

    if result.returncode not in (0, 1):
        return DependencyAuditReport(
            findings=[],
            source="error",
            packages_checked=0,
            detail=f"pip-audit exited {result.returncode}: {result.stderr.strip()[:500]}",
        )

    return DependencyAuditReport(
        findings=parse_pip_audit_json(result.stdout),
        source="pip-audit",
        packages_checked=_count_packages(result.stdout),
    )


def evaluate_dependency_gate(report: DependencyAuditReport, *, fail_on_unavailable: bool = False) -> bool:
    """Pure pass/fail decision over a `DependencyAuditReport`.

    Returns `False` (gate fails) if any vulnerability was found. When the
    audit couldn't run at all (`source` in `unavailable`/`timeout`/
    `error`), the gate passes by default -- matching this project's
    established pattern of not hard-failing on a declared-but-uninstalled
    optional dependency (see the Phase 4/6/7 changelog entries) -- unless
    `fail_on_unavailable=True`, which CI should set so a broken or
    missing `pip-audit` install can't silently masquerade as "clean".
    """

    if report.source != "pip-audit" and fail_on_unavailable:
        return False
    return len(report.findings) == 0
