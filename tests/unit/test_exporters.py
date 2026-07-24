"""Tests for cyberjection.reporting.exporters: JSONExporter and
MarkdownExporter, the two audit formats Task 6.3 asks for that the Phase 6
design spec's own code artifacts never actually included source for
(the spec's CLI sketch imports `JSONExporter` but the module's source is
absent from the spec)."""

from __future__ import annotations

import json

from cyberjection.reporting.exporters import JSONExporter, MarkdownExporter
from cyberjection.reporting.models import Finding


def _finding(rule_id: str, score: float, details: str = "details") -> Finding:
    return Finding(rule_id=rule_id, category="prompt_injection", score=score, details=details)


class TestJSONExporter:
    def test_writes_valid_json_with_summary_and_findings(self, tmp_path) -> None:
        findings = [_finding("CJ-001", 2.0), _finding("CJ-002", 8.5)]
        output_path = tmp_path / "report.json"

        JSONExporter.export(findings, output_path, threshold=7.0)
        payload = json.loads(output_path.read_text(encoding="utf-8"))

        assert payload["tool"] == "cyberjection"
        assert "generated_at" in payload
        assert len(payload["findings"]) == 2
        assert payload["findings"][0]["rule_id"] == "CJ-001"

    def test_summary_reflects_gate_outcome(self, tmp_path) -> None:
        findings = [_finding("CJ-001", 2.0), _finding("CJ-002", 8.5)]
        output_path = tmp_path / "report.json"

        JSONExporter.export(findings, output_path, threshold=7.0)
        payload = json.loads(output_path.read_text(encoding="utf-8"))

        assert payload["summary"]["total_findings"] == 2
        assert payload["summary"]["failing_findings"] == 1
        assert payload["summary"]["max_score"] == 8.5
        assert payload["summary"]["gate_passed"] is False

    def test_empty_findings_list_passes_gate_with_zero_max_score(self, tmp_path) -> None:
        output_path = tmp_path / "report.json"
        JSONExporter.export([], output_path, threshold=7.0)
        payload = json.loads(output_path.read_text(encoding="utf-8"))

        assert payload["summary"]["gate_passed"] is True
        assert payload["summary"]["max_score"] == 0.0
        assert payload["findings"] == []

    def test_creates_missing_parent_directories(self, tmp_path) -> None:
        output_path = tmp_path / "nested" / "dir" / "report.json"
        JSONExporter.export([_finding("CJ-001", 1.0)], output_path, threshold=7.0)

        assert output_path.exists()

    def test_round_trips_through_finding_model_validate(self, tmp_path) -> None:
        # A JSON export must be re-parseable back into `Finding` objects --
        # this is exactly what the CLI's `export` command relies on when
        # re-exporting a prior JSON report into SARIF or Markdown.
        findings = [_finding("CJ-001", 4.2, details="round-trip me")]
        output_path = tmp_path / "report.json"
        JSONExporter.export(findings, output_path, threshold=7.0)
        payload = json.loads(output_path.read_text(encoding="utf-8"))

        rebuilt = [Finding.model_validate(item) for item in payload["findings"]]
        assert rebuilt == findings


class TestMarkdownExporter:
    def test_header_reports_pass_when_gate_passed(self, tmp_path) -> None:
        output_path = tmp_path / "report.md"
        MarkdownExporter.export([_finding("CJ-001", 2.0)], output_path, threshold=7.0)
        text = output_path.read_text(encoding="utf-8")

        assert "**Quality gate:** PASSED" in text

    def test_header_reports_fail_when_gate_failed(self, tmp_path) -> None:
        output_path = tmp_path / "report.md"
        MarkdownExporter.export([_finding("CJ-001", 9.0)], output_path, threshold=7.0)
        text = output_path.read_text(encoding="utf-8")

        assert "**Quality gate:** FAILED" in text

    def test_table_contains_one_row_per_finding_with_correct_status(self, tmp_path) -> None:
        findings = [_finding("CJ-001", 2.0), _finding("CJ-002", 9.0)]
        output_path = tmp_path / "report.md"
        MarkdownExporter.export(findings, output_path, threshold=7.0)
        text = output_path.read_text(encoding="utf-8")

        assert "| CJ-001 | prompt_injection | 2.0 | PASS |" in text
        assert "| CJ-002 | prompt_injection | 9.0 | FAIL |" in text

    def test_pipe_characters_in_details_are_escaped_so_the_table_does_not_break(
        self, tmp_path
    ) -> None:
        finding = _finding("CJ-001", 1.0, details="response contained a | pipe character")
        output_path = tmp_path / "report.md"
        MarkdownExporter.export([finding], output_path, threshold=7.0)
        text = output_path.read_text(encoding="utf-8")

        assert "\\|" in text
        # Exactly one row line for this finding; an unescaped pipe would
        # have split it into extra spurious table columns/rows.
        row_lines = [line for line in text.splitlines() if line.startswith("| CJ-001")]
        assert len(row_lines) == 1

    def test_creates_missing_parent_directories(self, tmp_path) -> None:
        output_path = tmp_path / "nested" / "dir" / "report.md"
        MarkdownExporter.export([_finding("CJ-001", 1.0)], output_path, threshold=7.0)

        assert output_path.exists()
