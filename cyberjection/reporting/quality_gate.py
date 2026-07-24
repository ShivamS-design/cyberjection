"""CI/CD quality gate: pure threshold evaluation, decoupled from the CLI.

The Phase 6 design spec's Task 6.5 asks for "configurable pass/fail
thresholds in `cyberjection/config.py`" -- a flat top-level module that
does not exist in this codebase (configuration lives in the
`cyberjection.config` *package*: `schema.py` + `loader.py`, established in
Phase 1). Threading a threshold through that package as a
`QualityGateConfig` on `CampaignConfig` (see
`cyberjection.config.schema`) keeps quality-gate settings declarative and
version-controlled with the rest of a campaign, consistent with how
`RateLimitConfig` and `StrategyConfig` already work, rather than inventing
a second, disconnected configuration file.

The gate decision itself is kept here as a pure function with no CLI, I/O,
or Typer dependency at all -- mirroring Phase 4's
`cyberjection.persistence.resumability` split between a pure reconciliation
algorithm and its database-facing wrapper -- so `evaluate_quality_gate` is
fully unit-testable without spinning up a Typer command or a click
`CliRunner`.
"""

from __future__ import annotations

from typing import List, Optional

from cyberjection.reporting.models import Finding, QualityGateResult

DEFAULT_THRESHOLD = 7.0


def resolve_threshold(
    cli_threshold: Optional[float],
    config_threshold: Optional[float],
    *,
    default: float = DEFAULT_THRESHOLD,
) -> float:
    """Resolves the effective quality-gate threshold from, in descending
    priority: an explicit `--threshold` CLI flag, a campaign YAML's
    `quality_gate.threshold`, then the hardcoded default. An explicit `0.0`
    on the CLI is a legitimate ("fail on anything") threshold and must not
    be treated as "not given" -- hence the `is not None` checks rather than
    truthiness checks, which would incorrectly fall through past a real
    `0.0` override."""

    if cli_threshold is not None:
        return cli_threshold
    if config_threshold is not None:
        return config_threshold
    return default


def evaluate_quality_gate(findings: List[Finding], threshold: float) -> QualityGateResult:
    """Decides pass/fail for one evaluation run: fails if any finding's
    score meets or exceeds `threshold`, matching the Phase 6 spec's own
    `max_score >= threshold` comparison in its CLI sketch (a score exactly
    at the threshold fails the gate, not just scores above it)."""

    failing = [finding for finding in findings if finding.score >= threshold]
    max_score = max((finding.score for finding in findings), default=0.0)
    return QualityGateResult(
        passed=len(failing) == 0,
        threshold=threshold,
        max_score=max_score,
        failing_findings=failing,
    )
