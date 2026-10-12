"""Typed shapes shared by every HubGuard scanner (Phase 11).

Every scanner in `cyberjection.hubguard` -- pickle opcodes, remote code,
SafeTensors headers, secrets, weights -- emits the same `HubFinding`, and
`HubGuardReport` aggregates them into one verdict. Keeping one finding
type (rather than one per scanner) is what lets the risk score, the
verdict, and the Phase 6 exporters (SARIF/JSON/Markdown) treat every
supply-chain signal uniformly; see `HubGuardReport.to_reporting_findings`.

Risk scoring is deliberately simple and monotone, so an operator can
predict it from the findings list by hand:

- each severity maps to a fixed weight on the same 0-10 scale the Phase 6
  quality gate already uses (`SEVERITY_WEIGHTS`);
- the score is the single worst finding's weight, plus 10% of the sum of
  every other finding's weight, capped at 10.

So one HIGH finding scores 7.5, one HIGH plus three MEDIUMs scores 8.85,
and nothing can push a LOW-only report past a single HIGH. Adding a
finding can never lower the score.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Finding severity, lowest to highest. A `str` enum so it serializes
    as its plain value in JSON/SARIF output."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> float:
        return SEVERITY_WEIGHTS[self]

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)

    def bump(self) -> "Severity":
        """One level more severe (CRITICAL stays CRITICAL)."""

        return _SEVERITY_ORDER[min(self.rank + 1, len(_SEVERITY_ORDER) - 1)]


_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

SEVERITY_WEIGHTS: Dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 2.0,
    Severity.MEDIUM: 4.5,
    Severity.HIGH: 7.5,
    Severity.CRITICAL: 10.0,
}


class FindingCategory(str, Enum):
    PICKLE = "pickle"
    REMOTE_CODE = "remote_code"
    SANDBOX = "sandbox"
    SAFETENSORS = "safetensors"
    INTEGRITY = "integrity"
    SECRETS = "secrets"
    WEIGHTS = "weights"
    POLICY = "policy"
    PROVENANCE = "provenance"
    SCAN_ERROR = "scan_error"


class Verdict(str, Enum):
    """`PASS`: nothing at LOW or above. `WARN`: findings exist but none
    blocking and the score is within the policy ceiling. `BLOCK`: a
    blocking finding (every CRITICAL is blocking) or the score exceeds the
    policy's `max_allowed_risk_score`."""

    PASS = "PASS"
    WARN = "WARN"
    BLOCK = "BLOCK"


class HubFinding(BaseModel):
    """One supply-chain signal from any HubGuard scanner."""

    rule_id: str
    category: FindingCategory
    severity: Severity
    description: str
    file: Optional[str] = None
    line: Optional[int] = None
    evidence: Optional[str] = Field(
        default=None, description="Short, redacted excerpt -- never a raw secret."
    )
    remediation: Optional[str] = None
    blocking: bool = Field(
        default=False,
        description="Forces a BLOCK verdict regardless of the numeric risk score "
        "(policy violations, integrity failures). Every CRITICAL finding is blocking.",
    )

    def model_post_init(self, __context: Any) -> None:
        if self.severity == Severity.CRITICAL:
            object.__setattr__(self, "blocking", True)


class ScannedFile(BaseModel):
    path: str
    size: Optional[int] = None
    kind: str
    sha256: Optional[str] = None
    scanners: List[str] = Field(default_factory=list)


def compute_risk_score(findings: List[HubFinding]) -> float:
    """See the module docstring for the formula."""

    weights = sorted((f.severity.weight for f in findings), reverse=True)
    if not weights:
        return 0.0
    score = weights[0] + 0.1 * sum(weights[1:])
    return round(min(10.0, score), 2)


def decide_verdict(findings: List[HubFinding], risk_score: float, max_allowed_risk_score: float) -> Verdict:
    if any(f.blocking for f in findings) or risk_score > max_allowed_risk_score:
        return Verdict.BLOCK
    if any(f.severity.rank >= Severity.LOW.rank for f in findings):
        return Verdict.WARN
    return Verdict.PASS


def max_severity(findings: List[HubFinding]) -> Optional[Severity]:
    if not findings:
        return None
    return max((f.severity for f in findings), key=lambda s: s.rank)


class HubGuardReport(BaseModel):
    """The result of one `HubGuardClient.audit_repository()` run."""

    repo_id: str
    revision: str
    commit_sha: Optional[str] = None
    verdict: Verdict
    risk_score: float = Field(ge=0.0, le=10.0)
    max_allowed_risk_score: float
    findings: List[HubFinding] = Field(default_factory=list)
    files: List[ScannedFile] = Field(default_factory=list)
    incomplete: bool = Field(
        default=False,
        description="True if any scanner failed to finish; an incomplete scan never PASSes.",
    )
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_seconds: float = 0.0
    scanner_version: str = "0.11.0"

    @classmethod
    def build(
        cls,
        *,
        repo_id: str,
        revision: str,
        commit_sha: Optional[str],
        findings: List[HubFinding],
        files: List[ScannedFile],
        max_allowed_risk_score: float,
        started_at: datetime,
        duration_seconds: float,
    ) -> "HubGuardReport":
        ordered = sorted(findings, key=lambda f: (-f.severity.rank, f.category.value, f.file or "", f.line or 0))
        score = compute_risk_score(ordered)
        return cls(
            repo_id=repo_id,
            revision=revision,
            commit_sha=commit_sha,
            verdict=decide_verdict(ordered, score, max_allowed_risk_score),
            risk_score=score,
            max_allowed_risk_score=max_allowed_risk_score,
            findings=ordered,
            files=files,
            incomplete=any(f.category == FindingCategory.SCAN_ERROR for f in ordered),
            started_at=started_at,
            duration_seconds=duration_seconds,
        )

    @property
    def blocked(self) -> bool:
        return self.verdict == Verdict.BLOCK

    def findings_by_category(self) -> Dict[str, List[HubFinding]]:
        grouped: Dict[str, List[HubFinding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.category.value, []).append(finding)
        return grouped

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.model_dump(mode="json"), indent=indent)

    def to_reporting_findings(self) -> List["Any"]:
        """Adapts to the Phase 6 `reporting.Finding` shape so the existing
        SARIF/JSON/Markdown exporters and quality gate work unchanged on a
        HubGuard report."""

        from cyberjection.reporting.models import Finding

        results = []
        for finding in self.findings:
            location = f"hf://{self.repo_id}/{finding.file}" if finding.file else f"hf://{self.repo_id}"
            details = finding.description
            if finding.evidence:
                details += f" [evidence: {finding.evidence}]"
            results.append(
                Finding(
                    rule_id=f"hubguard.{finding.rule_id}",
                    category=f"supply-chain/{finding.category.value}",
                    score=finding.severity.weight,
                    details=details,
                    location=location,
                )
            )
        return results
