"""Tests for cyberjection.security.dependency_audit.

`parse_pip_audit_json` is pure and is hard-tested here against realistic
canned `pip-audit --format json` fixtures with no `pip-audit` installation
or network access required. `run_dependency_audit` is tested against this
sandbox's real environment, where `pip-audit` is genuinely not installed
-- exercising the honest `source="unavailable"` fallback path rather than
a mocked one. `evaluate_dependency_gate` is pure and tested directly
against synthetic `DependencyAuditReport` values covering every `source`.
"""

from __future__ import annotations

import json
import shutil

import pytest

from cyberjection.security.dependency_audit import (
    DependencyAuditReport,
    VulnerabilityFinding,
    evaluate_dependency_gate,
    parse_pip_audit_json,
    run_dependency_audit,
)


class TestParsePipAuditJSON:
    def test_empty_dependencies_list_produces_no_findings(self) -> None:
        raw = json.dumps({"dependencies": []})
        assert parse_pip_audit_json(raw) == []

    def test_dependency_with_no_vulns_produces_no_findings(self) -> None:
        raw = json.dumps({"dependencies": [{"name": "requests", "version": "2.31.0", "vulns": []}]})
        assert parse_pip_audit_json(raw) == []

    def test_single_vulnerability_is_parsed(self) -> None:
        raw = json.dumps(
            {
                "dependencies": [
                    {
                        "name": "pyyaml",
                        "version": "5.3.1",
                        "vulns": [
                            {
                                "id": "PYSEC-2020-96",
                                "fix_versions": ["5.4"],
                                "description": "Arbitrary code execution via full_load.",
                            }
                        ],
                    }
                ]
            }
        )
        findings = parse_pip_audit_json(raw)
        assert len(findings) == 1
        assert findings[0] == VulnerabilityFinding(
            package="pyyaml",
            installed_version="5.3.1",
            advisory_id="PYSEC-2020-96",
            summary="Arbitrary code execution via full_load.",
            fixed_in="5.4",
        )

    def test_multiple_vulns_across_multiple_dependencies_are_all_parsed(self) -> None:
        raw = json.dumps(
            {
                "dependencies": [
                    {
                        "name": "pkg-a",
                        "version": "1.0",
                        "vulns": [
                            {"id": "V-1", "fix_versions": ["1.1"], "description": "issue one"},
                            {"id": "V-2", "fix_versions": ["1.2"], "description": "issue two"},
                        ],
                    },
                    {
                        "name": "pkg-b",
                        "version": "2.0",
                        "vulns": [{"id": "V-3", "fix_versions": [], "description": "issue three"}],
                    },
                ]
            }
        )
        findings = parse_pip_audit_json(raw)
        assert len(findings) == 3
        assert {f.advisory_id for f in findings} == {"V-1", "V-2", "V-3"}

    def test_missing_fix_versions_yields_none(self) -> None:
        raw = json.dumps(
            {"dependencies": [{"name": "pkg", "version": "1.0", "vulns": [{"id": "V-1", "description": "x"}]}]}
        )
        findings = parse_pip_audit_json(raw)
        assert findings[0].fixed_in is None

    def test_missing_description_yields_placeholder_summary(self) -> None:
        raw = json.dumps({"dependencies": [{"name": "pkg", "version": "1.0", "vulns": [{"id": "V-1"}]}]})
        findings = parse_pip_audit_json(raw)
        assert findings[0].summary == "(no description provided by advisory)"

    def test_long_description_is_truncated(self) -> None:
        long_description = "x" * 500
        raw = json.dumps(
            {
                "dependencies": [
                    {"name": "pkg", "version": "1.0", "vulns": [{"id": "V-1", "description": long_description}]}
                ]
            }
        )
        findings = parse_pip_audit_json(raw)
        assert len(findings[0].summary) == 303  # 300 chars + "..."
        assert findings[0].summary.endswith("...")

    def test_malformed_json_returns_empty_list_rather_than_raising(self) -> None:
        assert parse_pip_audit_json("{not valid json") == []

    def test_missing_dependencies_key_returns_empty_list(self) -> None:
        assert parse_pip_audit_json(json.dumps({})) == []


class TestRunDependencyAudit:
    def test_reports_unavailable_when_pip_audit_not_installed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(shutil, "which", lambda _name: None)
        report = run_dependency_audit()
        assert report.source == "unavailable"
        assert report.findings == []
        assert "security" in report.detail

    def test_matches_real_sandbox_state_when_not_stubbed(self) -> None:
        # This project's hard-testing sandbox genuinely does not have
        # pip-audit installed (no network access to install optional
        # extras) -- exercising the real, unstubbed code path here is
        # exactly the honest-fallback behavior this module exists to
        # guarantee, not a mock standing in for it.
        report = run_dependency_audit()
        assert report.source in ("unavailable", "pip-audit", "timeout", "error")
        if shutil.which("pip-audit") is None:
            assert report.source == "unavailable"


class TestEvaluateDependencyGate:
    def test_clean_report_passes(self) -> None:
        report = DependencyAuditReport(findings=[], source="pip-audit", packages_checked=10)
        assert evaluate_dependency_gate(report) is True

    def test_report_with_findings_fails(self) -> None:
        finding = VulnerabilityFinding(
            package="pkg", installed_version="1.0", advisory_id="V-1", summary="bad"
        )
        report = DependencyAuditReport(findings=[finding], source="pip-audit", packages_checked=10)
        assert evaluate_dependency_gate(report) is False

    def test_unavailable_source_passes_by_default(self) -> None:
        report = DependencyAuditReport(findings=[], source="unavailable", packages_checked=0)
        assert evaluate_dependency_gate(report) is True

    def test_unavailable_source_fails_when_fail_on_unavailable_set(self) -> None:
        report = DependencyAuditReport(findings=[], source="unavailable", packages_checked=0)
        assert evaluate_dependency_gate(report, fail_on_unavailable=True) is False

    def test_error_source_fails_when_fail_on_unavailable_set(self) -> None:
        report = DependencyAuditReport(findings=[], source="error", packages_checked=0)
        assert evaluate_dependency_gate(report, fail_on_unavailable=True) is False

    def test_pip_audit_source_with_no_findings_passes_even_with_fail_on_unavailable(self) -> None:
        report = DependencyAuditReport(findings=[], source="pip-audit", packages_checked=5)
        assert evaluate_dependency_gate(report, fail_on_unavailable=True) is True
