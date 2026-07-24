"""Tests for cyberjection.security.compliance.

Exercises `generate_compliance_report` and `compliance_summary` against
both the real, shipped `CONTROL_REGISTRY` (so a future edit that breaks
rendering or accidentally introduces a duplicate/malformed entry is
caught) and small synthetic registries (so the grouping/counting logic
itself is verified independent of the current registry's exact contents).
"""

from __future__ import annotations

from cyberjection.security.compliance import (
    ASVS,
    SOC2,
    CONTROL_REGISTRY,
    ControlMapping,
    ControlStatus,
    compliance_summary,
    generate_compliance_report,
)


class TestControlRegistry:
    def test_registry_is_non_empty(self) -> None:
        assert len(CONTROL_REGISTRY) > 0

    def test_every_control_id_is_unique(self) -> None:
        ids = [c.control_id for c in CONTROL_REGISTRY]
        assert len(ids) == len(set(ids))

    def test_every_implemented_control_has_at_least_one_evidence_entry(self) -> None:
        for control in CONTROL_REGISTRY:
            if control.status == ControlStatus.IMPLEMENTED:
                assert control.evidence, f"{control.control_id} is IMPLEMENTED but has no evidence"

    def test_every_control_belongs_to_a_known_framework(self) -> None:
        for control in CONTROL_REGISTRY:
            assert control.framework in (ASVS, SOC2)

    def test_not_applicable_controls_have_a_note_explaining_why(self) -> None:
        for control in CONTROL_REGISTRY:
            if control.status == ControlStatus.NOT_APPLICABLE:
                assert control.notes, f"{control.control_id} is NOT_APPLICABLE but has no explanatory note"


class TestComplianceSummary:
    def test_default_registry_summary_counts_match_manual_count(self) -> None:
        summary = compliance_summary()
        manual_counts = {status.value: 0 for status in ControlStatus}
        for control in CONTROL_REGISTRY:
            manual_counts[control.status.value] += 1
        assert summary == manual_counts

    def test_summary_total_equals_registry_length(self) -> None:
        summary = compliance_summary()
        assert sum(summary.values()) == len(CONTROL_REGISTRY)

    def test_summary_includes_all_status_keys_even_if_zero(self) -> None:
        registry = [
            ControlMapping(
                control_id="X-1",
                framework=ASVS,
                title="Test control",
                status=ControlStatus.IMPLEMENTED,
                evidence=("test.py",),
            )
        ]
        summary = compliance_summary(registry)
        assert summary == {
            "IMPLEMENTED": 1,
            "PARTIAL": 0,
            "NOT_APPLICABLE": 0,
            "NOT_IMPLEMENTED": 0,
        }

    def test_empty_registry_summary_is_all_zero(self) -> None:
        summary = compliance_summary([])
        assert sum(summary.values()) == 0


class TestGenerateComplianceReport:
    def test_default_registry_report_is_nonempty_markdown(self) -> None:
        report = generate_compliance_report()
        assert isinstance(report, str)
        assert len(report) > 0
        assert "|" in report  # renders as Markdown tables

    def test_report_contains_a_heading_for_each_framework_present(self) -> None:
        report = generate_compliance_report()
        assert f"## {ASVS}" in report
        assert f"## {SOC2}" in report

    def test_report_contains_every_control_id(self) -> None:
        report = generate_compliance_report()
        for control in CONTROL_REGISTRY:
            assert control.control_id in report

    def test_synthetic_registry_groups_controls_by_framework_in_first_seen_order(self) -> None:
        registry = [
            ControlMapping("A-1", ASVS, "First ASVS", ControlStatus.IMPLEMENTED, ("e1",)),
            ControlMapping("S-1", SOC2, "First SOC2", ControlStatus.IMPLEMENTED, ("e2",)),
            ControlMapping("A-2", ASVS, "Second ASVS", ControlStatus.PARTIAL, ("e3",), notes="n"),
        ]
        report = generate_compliance_report(registry)
        asvs_heading_index = report.index(f"## {ASVS}")
        soc2_heading_index = report.index(f"## {SOC2}")
        a2_index = report.index("A-2")
        assert asvs_heading_index < soc2_heading_index
        # A-2 (second ASVS control) must still appear under the ASVS
        # section, i.e. before the SOC2 heading, even though it isn't
        # adjacent to A-1 in the input list.
        assert asvs_heading_index < a2_index < soc2_heading_index

    def test_missing_evidence_renders_as_dash(self) -> None:
        registry = [
            ControlMapping("X-1", ASVS, "No evidence yet", ControlStatus.NOT_IMPLEMENTED, ())
        ]
        report = generate_compliance_report(registry)
        assert "| X-1 | No evidence yet | NOT_IMPLEMENTED | - |" in report

    def test_missing_notes_renders_as_dash(self) -> None:
        registry = [
            ControlMapping("X-1", ASVS, "No notes", ControlStatus.IMPLEMENTED, ("e1",))
        ]
        report = generate_compliance_report(registry)
        assert report.strip().endswith("| e1 | -") or "| `e1` | -" in report

    def test_multiline_notes_are_flattened_to_a_single_line(self) -> None:
        registry = [
            ControlMapping(
                "X-1",
                ASVS,
                "Multiline note test",
                ControlStatus.PARTIAL,
                ("e1",),
                notes="line one\nline two",
            )
        ]
        report = generate_compliance_report(registry)
        assert "line one line two" in report
        assert "line one\nline two" not in report
