"""Tests for cyberjection.cli.main: argument parsing and exit-code behavior
for the `run`, `inspect`, and `export` commands.

Requires `typer`/`click`/`rich` to be importable. This sandbox has no
network access to install the real `typer`/`rich` packages, so these run
through this project's own offline shims (built directly on the real
`click` library, which *is* installed -- typer is itself a thin layer over
click) rather than against a mock CLI framework; see the module docstring
in the shim itself for why this is real command-dispatch behavior, not a
simulation of it. `pytest.importorskip` guards this file the same way
`test_repository.py` guards on `sqlalchemy`, in case a future environment
runs this suite without even the shims on `sys.path`.
"""

from __future__ import annotations

import json

import pytest

typer = pytest.importorskip("typer")
from typer.testing import CliRunner  # noqa: E402

from cyberjection.cli.main import EXIT_ENVIRONMENT_ERROR  # noqa: E402
from cyberjection.cli.main import (  # noqa: E402
    EXIT_OK,
    EXIT_QUALITY_GATE_FAILED,
    EXIT_USAGE_ERROR,
    app,
)

runner = CliRunner()

VALID_CONFIG = """
name: "CLI Test Campaign"
targets:
  - id: "support-agent"
    provider: "openai"
    model: "gpt-4o-mini"
    api_key: "test-key-not-a-secret"
quality_gate:
  threshold: 5.0
"""


@pytest.fixture
def config_path(tmp_path):
    path = tmp_path / "campaign.yaml"
    path.write_text(VALID_CONFIG, encoding="utf-8")
    return path


class TestHelp:
    def test_top_level_help_exits_zero(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == EXIT_OK
        assert "run" in result.output
        assert "inspect" in result.output
        assert "export" in result.output

    def test_run_help_lists_documented_flags(self) -> None:
        result = runner.invoke(app, ["run", "--help"])
        assert result.exit_code == EXIT_OK
        assert "--config" in result.output
        assert "--target" in result.output
        assert "--threshold" in result.output


class TestRunArgumentParsing:
    def test_missing_required_target_exits_usage_error(self, config_path) -> None:
        result = runner.invoke(app, ["run", "--config", str(config_path)])
        assert result.exit_code == EXIT_USAGE_ERROR

    def test_missing_config_file_reports_config_error(self, tmp_path) -> None:
        missing = tmp_path / "does-not-exist.yaml"
        result = runner.invoke(app, ["run", "--config", str(missing), "--target", "support-agent"])
        assert result.exit_code == EXIT_USAGE_ERROR
        assert "Configuration error" in result.output

    def test_unknown_target_id_reports_target_error(self, config_path) -> None:
        result = runner.invoke(
            app, ["run", "--config", str(config_path), "--target", "no-such-target"]
        )
        assert result.exit_code == EXIT_USAGE_ERROR
        assert "Target error" in result.output
        assert "support-agent" in result.output  # known ids listed for the operator


class TestRunQualityGateExitCodes:
    def test_low_threshold_fails_the_gate(self, config_path) -> None:
        # The stub pipeline's findings top out at score 3.4; a threshold
        # below that must fail the gate (exit 1), not pass silently.
        result = runner.invoke(
            app,
            [
                "run",
                "--config",
                str(config_path),
                "--target",
                "support-agent",
                "--threshold",
                "1.0",
            ],
        )
        assert result.exit_code == EXIT_QUALITY_GATE_FAILED
        assert "QUALITY GATE FAILED" in result.output

    def test_high_threshold_passes_the_gate(self, config_path) -> None:
        result = runner.invoke(
            app,
            [
                "run",
                "--config",
                str(config_path),
                "--target",
                "support-agent",
                "--threshold",
                "9.9",
            ],
        )
        assert result.exit_code == EXIT_OK
        assert "QUALITY GATE PASSED" in result.output

    def test_no_cli_threshold_falls_back_to_campaign_quality_gate_threshold(
        self, config_path
    ) -> None:
        # VALID_CONFIG declares quality_gate.threshold: 5.0; the stub's max
        # finding score is 3.4, so omitting --threshold entirely should
        # still pass (3.4 < 5.0), proving the CLI actually reads the
        # campaign's declared threshold rather than silently defaulting.
        result = runner.invoke(
            app, ["run", "--config", str(config_path), "--target", "support-agent"]
        )
        assert result.exit_code == EXIT_OK

    def test_summary_table_lists_every_finding(self, config_path) -> None:
        result = runner.invoke(
            app,
            ["run", "--config", str(config_path), "--target", "support-agent", "--threshold", "9.9"],
        )
        assert "CJ-001" in result.output
        assert "CJ-002" in result.output


class TestRunExportFlags:
    def test_writes_sarif_json_and_markdown_when_requested(self, config_path, tmp_path) -> None:
        sarif_path = tmp_path / "out.sarif"
        json_path = tmp_path / "out.json"
        md_path = tmp_path / "out.md"

        result = runner.invoke(
            app,
            [
                "run",
                "--config",
                str(config_path),
                "--target",
                "support-agent",
                "--threshold",
                "9.9",
                "--sarif-out",
                str(sarif_path),
                "--json-out",
                str(json_path),
                "--markdown-out",
                str(md_path),
            ],
        )

        assert result.exit_code == EXIT_OK
        assert sarif_path.exists()
        assert json_path.exists()
        assert md_path.exists()

    def test_no_export_flags_writes_no_files(self, config_path, tmp_path) -> None:
        before = set(tmp_path.iterdir())
        runner.invoke(
            app,
            ["run", "--config", str(config_path), "--target", "support-agent", "--threshold", "9.9"],
        )
        after = set(tmp_path.iterdir())
        assert before == after


@pytest.fixture
def json_report(tmp_path):
    payload = {
        "tool": "cyberjection",
        "findings": [
            {"rule_id": "CJ-001", "category": "prompt_injection", "score": 2.0, "details": "d"},
            {"rule_id": "CJ-002", "category": "jailbreak", "score": 9.0, "details": "d2"},
        ],
    }
    path = tmp_path / "prior_run.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


class TestExportCommand:
    def test_export_to_sarif(self, json_report, tmp_path) -> None:
        out = tmp_path / "converted.sarif"
        result = runner.invoke(
            app, ["export", "--from-json", str(json_report), "--output", str(out), "--format", "sarif"]
        )
        assert result.exit_code == EXIT_OK
        assert out.exists()
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["version"] == "2.1.0"

    def test_export_to_markdown(self, json_report, tmp_path) -> None:
        out = tmp_path / "converted.md"
        result = runner.invoke(
            app,
            ["export", "--from-json", str(json_report), "--output", str(out), "--format", "markdown"],
        )
        assert result.exit_code == EXIT_OK
        assert "Cyberjection Security Evaluation Report" in out.read_text(encoding="utf-8")

    def test_unsupported_format_is_a_usage_error(self, json_report, tmp_path) -> None:
        out = tmp_path / "converted.txt"
        result = runner.invoke(
            app, ["export", "--from-json", str(json_report), "--output", str(out), "--format", "yaml"]
        )
        assert result.exit_code == EXIT_USAGE_ERROR
        assert not out.exists()

    def test_missing_input_file_is_a_usage_error(self, tmp_path) -> None:
        missing = tmp_path / "nope.json"
        out = tmp_path / "converted.sarif"
        result = runner.invoke(app, ["export", "--from-json", str(missing), "--output", str(out)])
        assert result.exit_code == EXIT_USAGE_ERROR


class TestInspectCommand:
    def test_reports_environment_error_when_sqlalchemy_unavailable(self, monkeypatch) -> None:
        monkeypatch.setattr("cyberjection.persistence._SQLALCHEMY_AVAILABLE", False)
        result = runner.invoke(app, ["inspect"])
        assert result.exit_code == EXIT_ENVIRONMENT_ERROR
        assert "unavailable" in result.output.lower()

    def test_renders_campaigns_when_persistence_available(self, monkeypatch) -> None:
        # Exercises the `inspect` command's rendering path without a real
        # SQLAlchemy/aiosqlite install: `_inspect_async` (the only piece
        # that actually touches the database) is swapped for a fake
        # returning canned rows, isolating this test to the CLI's own
        # table-rendering logic -- which is what this test file is for.
        import cyberjection.cli.main as cli_main

        async def _fake_inspect_async(db_url, limit):
            return [("camp-1", "nightly-run", "COMPLETED", "2026-01-01T00:00:00")]

        monkeypatch.setattr("cyberjection.persistence._SQLALCHEMY_AVAILABLE", True)
        monkeypatch.setattr(cli_main, "_inspect_async", _fake_inspect_async)

        result = runner.invoke(app, ["inspect"])
        assert result.exit_code == EXIT_OK
        assert "camp-1" in result.output
        assert "nightly-run" in result.output

    def test_no_campaigns_prints_a_clear_empty_message(self, monkeypatch) -> None:
        import cyberjection.cli.main as cli_main

        async def _fake_inspect_async(db_url, limit):
            return []

        monkeypatch.setattr("cyberjection.persistence._SQLALCHEMY_AVAILABLE", True)
        monkeypatch.setattr(cli_main, "_inspect_async", _fake_inspect_async)

        result = runner.invoke(app, ["inspect"])
        assert result.exit_code == EXIT_OK
        assert "No campaigns found" in result.output
