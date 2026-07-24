"""Tests for cyberjection.reporting.sarif.SARIFReporter.

Covers the two bugs fixed relative to the Phase 6 design spec's own
`SARIFReporter.export` sketch (duplicate `rules` entries for a
repeated rule id, and severity hardcoded at a fixed 7.0 regardless of the
run's actual `--threshold`), plus a structural check of the exported JSON
against a locally-authored minimal SARIF 2.1.0 schema -- this sandbox has
no network access to fetch and validate against the full ~300KB official
`sarif-schema-2.1.0.json`, so the structural subset asserted here (present
here as an explicit, hand-written `jsonschema` document, itself unit-tested
for internal consistency) is what "hard-tested offline" means for this
exporter; see docs/TESTING.md.
"""

from __future__ import annotations

import json

import jsonschema
import pytest

from cyberjection.reporting.models import Finding
from cyberjection.reporting.sarif import SARIFReporter

# A trimmed structural subset of the official SARIF 2.1.0 JSON schema --
# just the fields this exporter actually emits and that a SARIF consumer
# (GitHub code scanning, GitLab's Security Dashboard) requires to ingest a
# report at all. Not a substitute for validating against the full official
# schema, which would need network access this sandbox doesn't have.
_MINIMAL_SARIF_SCHEMA = {
    "type": "object",
    "required": ["$schema", "version", "runs"],
    "properties": {
        "$schema": {"type": "string"},
        "version": {"type": "string", "const": "2.1.0"},
        "runs": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["tool", "results"],
                "properties": {
                    "tool": {
                        "type": "object",
                        "required": ["driver"],
                        "properties": {
                            "driver": {
                                "type": "object",
                                "required": ["name", "rules"],
                                "properties": {
                                    "name": {"type": "string"},
                                    "rules": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "required": ["id", "shortDescription"],
                                        },
                                    },
                                },
                            }
                        },
                    },
                    "results": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["ruleId", "ruleIndex", "level", "message", "locations"],
                            "properties": {
                                "level": {"enum": ["error", "warning", "note", "none"]},
                                "message": {
                                    "type": "object",
                                    "required": ["text"],
                                },
                                "locations": {"type": "array", "minItems": 1},
                            },
                        },
                    },
                },
            },
        },
    },
}


def _finding(rule_id: str, score: float, category: str = "prompt_injection") -> Finding:
    return Finding(rule_id=rule_id, category=category, score=score, details="details")


class TestSARIFStructuralValidity:
    def test_exported_report_matches_minimal_sarif_schema(self, tmp_path) -> None:
        findings = [_finding("CJ-001", 2.0), _finding("CJ-002", 8.5)]
        output_path = tmp_path / "report.sarif"

        SARIFReporter.export(findings, output_path, threshold=7.0)
        payload = json.loads(output_path.read_text(encoding="utf-8"))

        jsonschema.validate(payload, _MINIMAL_SARIF_SCHEMA)

    def test_output_file_ends_with_trailing_newline(self, tmp_path) -> None:
        output_path = tmp_path / "report.sarif"
        SARIFReporter.export([_finding("CJ-001", 1.0)], output_path, threshold=7.0)

        assert output_path.read_text(encoding="utf-8").endswith("\n")


class TestSARIFRuleDeduplication:
    """Regression coverage for the spec's own duplicate-`rules`-entry bug."""

    def test_repeated_rule_id_produces_one_rules_catalog_entry(self, tmp_path) -> None:
        findings = [
            _finding("CJ-001", 2.0, category="prompt_injection"),
            _finding("CJ-001", 6.0, category="prompt_injection"),
            _finding("CJ-001", 9.0, category="prompt_injection"),
        ]
        output_path = tmp_path / "report.sarif"
        SARIFReporter.export(findings, output_path, threshold=7.0)
        payload = json.loads(output_path.read_text(encoding="utf-8"))

        rules = payload["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "CJ-001"

    def test_every_result_ruleindex_points_at_the_single_catalog_entry(self, tmp_path) -> None:
        findings = [_finding("CJ-001", 2.0), _finding("CJ-001", 6.0), _finding("CJ-001", 9.0)]
        output_path = tmp_path / "report.sarif"
        SARIFReporter.export(findings, output_path, threshold=7.0)
        payload = json.loads(output_path.read_text(encoding="utf-8"))

        results = payload["runs"][0]["results"]
        assert all(result["ruleIndex"] == 0 for result in results)
        # All three results are still present -- deduplication only
        # collapses the *rules catalog*, never the per-finding results.
        assert len(results) == 3

    def test_distinct_rule_ids_each_get_their_own_catalog_entry_in_order(self, tmp_path) -> None:
        findings = [_finding("CJ-001", 2.0), _finding("CJ-002", 6.0), _finding("CJ-001", 3.0)]
        output_path = tmp_path / "report.sarif"
        SARIFReporter.export(findings, output_path, threshold=7.0)
        payload = json.loads(output_path.read_text(encoding="utf-8"))

        rules = payload["runs"][0]["tool"]["driver"]["rules"]
        assert [r["id"] for r in rules] == ["CJ-001", "CJ-002"]

        results = payload["runs"][0]["results"]
        # Third finding reuses CJ-001's existing catalog entry (index 0),
        # not a new one.
        assert [r["ruleIndex"] for r in results] == [0, 1, 0]


class TestSARIFThresholdAwareSeverity:
    """Regression coverage for the spec's hardcoded-7.0-severity bug."""

    def test_severity_is_relative_to_the_configured_threshold_not_a_fixed_7(
        self, tmp_path
    ) -> None:
        # A finding scoring 5.0 has already failed a --threshold 4.0 run,
        # so it must be reported as "error", even though 5.0 < 7.0 (the
        # spec's hardcoded cutoff).
        output_path = tmp_path / "report.sarif"
        SARIFReporter.export([_finding("CJ-001", 5.0)], output_path, threshold=4.0)
        payload = json.loads(output_path.read_text(encoding="utf-8"))

        result = payload["runs"][0]["results"][0]
        rule = payload["runs"][0]["tool"]["driver"]["rules"][0]
        assert result["level"] == "error"
        assert rule["defaultConfiguration"]["level"] == "error"

    def test_finding_below_threshold_is_reported_as_note_and_warning(self, tmp_path) -> None:
        output_path = tmp_path / "report.sarif"
        SARIFReporter.export([_finding("CJ-001", 3.0)], output_path, threshold=7.0)
        payload = json.loads(output_path.read_text(encoding="utf-8"))

        result = payload["runs"][0]["results"][0]
        rule = payload["runs"][0]["tool"]["driver"]["rules"][0]
        assert result["level"] == "note"
        assert rule["defaultConfiguration"]["level"] == "warning"

    def test_score_exactly_at_threshold_is_error(self, tmp_path) -> None:
        output_path = tmp_path / "report.sarif"
        SARIFReporter.export([_finding("CJ-001", 7.0)], output_path, threshold=7.0)
        payload = json.loads(output_path.read_text(encoding="utf-8"))

        assert payload["runs"][0]["results"][0]["level"] == "error"

    def test_default_threshold_matches_spec_hardcoded_value_when_unspecified(
        self, tmp_path
    ) -> None:
        # export()'s own default threshold (7.0) reproduces the spec's
        # original hardcoded behavior for callers that don't pass one.
        output_path = tmp_path / "report.sarif"
        SARIFReporter.export([_finding("CJ-001", 7.0)], output_path)
        payload = json.loads(output_path.read_text(encoding="utf-8"))

        assert payload["runs"][0]["results"][0]["level"] == "error"
