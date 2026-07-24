"""Enterprise security reporting: typed findings, a SARIF 2.1.0 exporter,
Markdown/JSON audit exporters, and the pass/fail quality-gate evaluator
CI/CD pipelines gate on.

`Finding` is the one shape every reporter in this package consumes, so a
result produced anywhere upstream (the CLI's evaluation pipeline today,
an orchestrator in a later phase) can be exported to any format without
each exporter growing its own conversion logic.
"""

from __future__ import annotations

from cyberjection.reporting.exporters import JSONExporter, MarkdownExporter
from cyberjection.reporting.models import Finding, QualityGateResult
from cyberjection.reporting.quality_gate import evaluate_quality_gate, resolve_threshold
from cyberjection.reporting.sarif import SARIFReporter

__all__ = [
    "Finding",
    "QualityGateResult",
    "SARIFReporter",
    "JSONExporter",
    "MarkdownExporter",
    "evaluate_quality_gate",
    "resolve_threshold",
]
