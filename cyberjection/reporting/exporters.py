"""Multi-format audit exporters: machine-readable JSON logs and executive
Markdown summaries.

The Phase 6 design spec's CLI artifact imports `JSONExporter` from this
module but does not include this module's own source among its code
artifacts. Implemented here to match the CLI's expected
`JSONExporter.export(results, output_path)` call shape, plus a
`MarkdownExporter` covering the "executive Markdown summaries" half of
Task 6.3 that the spec's artifacts never actually wrote.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from cyberjection.reporting.models import Finding


def _summary(findings: List[Finding], threshold: float) -> dict:
    failing = [f for f in findings if f.score >= threshold]
    max_score = max((f.score for f in findings), default=0.0)
    return {
        "total_findings": len(findings),
        "failing_findings": len(failing),
        "max_score": max_score,
        "threshold": threshold,
        "gate_passed": max_score < threshold,
    }


class JSONExporter:
    """Machine-readable JSON audit log: the full finding list plus a
    summary block, suitable for ingestion by a SIEM or a downstream
    reporting pipeline that doesn't speak SARIF."""

    @staticmethod
    def export(findings: List[Finding], output_path: Path, *, threshold: float = 7.0) -> None:
        payload = {
            "tool": "cyberjection",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": _summary(findings, threshold),
            "findings": [finding.model_dump() for finding in findings],
        }

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")


class MarkdownExporter:
    """Executive Markdown summary: a short pass/fail header plus a
    per-finding table, meant to be pasted into a pull request comment or
    an audit ticket rather than parsed by tooling."""

    @staticmethod
    def export(findings: List[Finding], output_path: Path, *, threshold: float = 7.0) -> None:
        summary = _summary(findings, threshold)
        lines = [
            "# Cyberjection Security Evaluation Report",
            "",
            f"**Quality gate:** {'PASSED' if summary['gate_passed'] else 'FAILED'} "
            f"(threshold {threshold:.1f}, max score {summary['max_score']:.1f})",
            "",
            f"- Total findings: {summary['total_findings']}",
            f"- Findings at or above threshold: {summary['failing_findings']}",
            "",
            "| Rule ID | Category | Score | Status | Details |",
            "|---|---|---|---|---|",
        ]
        for finding in findings:
            status = "FAIL" if finding.score >= threshold else "PASS"
            details = finding.details.replace("|", "\\|")
            lines.append(
                f"| {finding.rule_id} | {finding.category} | {finding.score:.1f} | {status} | {details} |"
            )
        lines.append("")

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(lines), encoding="utf-8")
