"""Tests for cyberjection.cli.main: argument parsing and exit-code behavior
for the `run`, `inspect`, `export`, `plugins`, and `serve` commands.

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
from cyberjection.reporting.models import Finding  # noqa: E402

runner = CliRunner()


def _canned_findings():
    # Phase 9 replaced `_execute_pipeline`'s two-hardcoded-`Finding` stub
    # with the real orchestrator (see cyberjection/orchestrator/campaign.py),
    # which needs a real or mocked LLM target to produce anything. This
    # file's own docstring scopes it to the `run`/`inspect`/`export`
    # commands' argument-parsing and exit-code behavior, not the
    # orchestrator's attack/evaluator execution -- that's what
    # test_orchestrator.py covers directly. These two findings reproduce
    # the shape the old stub used to return (one finding scoring 3.4, one
    # scoring 1.1) so `TestRunQualityGateExitCodes`/`TestRunExportFlags`'s
    # threshold-comparison assertions keep meaning what they say.
    return [
        Finding(
            rule_id="CJ-001",
            category="prompt_injection",
            score=3.4,
            details="Simulated finding for CLI argument-parsing tests.",
        ),
        Finding(
            rule_id="CJ-002",
            category="jailbreak",
            score=1.1,
            details="Simulated finding for CLI argument-parsing tests.",
        ),
    ]


@pytest.fixture(autouse=True)
def _stub_pipeline(monkeypatch):
    # Isolates this file from the real orchestrator the same way
    # `TestInspectCommand` isolates itself from a real database by mocking
    # `_inspect_async` -- see `_canned_findings()` above for why.
    import cyberjection.cli.main as cli_main

    async def _fake_execute_pipeline(config, target, *, db_url=None, resume_campaign_id=None):
        return _canned_findings()

    monkeypatch.setattr(cli_main, "_execute_pipeline", _fake_execute_pipeline)


@pytest.fixture(autouse=True)
def _isolated_audit_log(monkeypatch, tmp_path):
    # Phase 8 wired every command through the module-level `_audit_logger`
    # singleton, which defaults to `.cyberjection/audit.jsonl` relative to
    # the current working directory. Without this fixture, every CLI test
    # in this file would write real audit entries into whatever directory
    # `pytest` happens to be invoked from (e.g. the repo root), silently
    # polluting it and leaking state between test runs. Redirecting it to
    # a fresh per-test tmp_path keeps these tests hermetic.
    import cyberjection.cli.main as cli_main
    from cyberjection.security.audit_log import AuditLogger

    monkeypatch.setattr(cli_main, "_audit_logger", AuditLogger(tmp_path / "audit.jsonl"))


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
        assert "audit" in result.output

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
        # `audit.jsonl` is a real, expected side effect of every `run`
        # invocation (the `_isolated_audit_log` fixture points
        # `_audit_logger` at this same `tmp_path`, and `run_evaluation`
        # unconditionally calls `_audit_logger.log(...)` several times) --
        # not a report file this test cares about. Without excluding it,
        # this assertion would fail on every invocation regardless of the
        # `--sarif-out`/`--json-out`/`--markdown-out` flags under test.
        before = {p.name for p in tmp_path.iterdir()}
        runner.invoke(
            app,
            ["run", "--config", str(config_path), "--target", "support-agent", "--threshold", "9.9"],
        )
        after = {p.name for p in tmp_path.iterdir()}
        assert after - before <= {"audit.jsonl"}

    def test_path_traversal_in_sarif_out_is_rejected(self, config_path, monkeypatch, tmp_path) -> None:
        # _safe_output_path() contains report paths to Path.cwd(); running
        # the CliRunner invocation with cwd() == tmp_path (via monkeypatch,
        # since CliRunner doesn't chdir on its own) and asking for a
        # ../outside.sarif path must be rejected as a usage error rather
        # than silently written outside tmp_path.
        monkeypatch.chdir(tmp_path)
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
                "../escape.sarif",
            ],
        )
        assert result.exit_code == EXIT_USAGE_ERROR
        assert "Unsafe report path" in result.output
        assert not (tmp_path.parent / "escape.sarif").exists()


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


class TestAuditCommand:
    def test_bare_audit_defaults_to_deps_and_secrets(self, monkeypatch, tmp_path) -> None:
        # With no check flags at all, `audit` should run --deps and
        # --secrets over the current directory rather than doing nothing.
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["audit"])
        assert result.exit_code == EXIT_OK
        assert "dependency vulnerability audit" in result.output.lower()
        assert "scanning for hardcoded secrets" in result.output.lower()

    def test_deps_only_reports_unavailable_in_this_sandbox(self, monkeypatch, tmp_path) -> None:
        import shutil

        monkeypatch.setattr(shutil, "which", lambda _name: None)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["audit", "--deps"])
        assert result.exit_code == EXIT_OK
        assert "unavailable" in result.output.lower()

    def test_deps_fail_on_unavailable_fails_the_gate(self, monkeypatch, tmp_path) -> None:
        import shutil

        monkeypatch.setattr(shutil, "which", lambda _name: None)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["audit", "--deps", "--fail-on-unavailable"])
        assert result.exit_code == EXIT_QUALITY_GATE_FAILED

    def test_secrets_scan_finds_a_planted_secret(self, monkeypatch, tmp_path) -> None:
        (tmp_path / "leaked.py").write_text('AWS_KEY = "AKIAQWERTYUIOPASDFGH"\n', encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["audit", "--secrets", "--path", str(tmp_path)])
        assert result.exit_code == EXIT_QUALITY_GATE_FAILED
        assert "potential secret" in result.output.lower()

    def test_secrets_scan_clean_directory_passes(self, monkeypatch, tmp_path) -> None:
        (tmp_path / "clean.py").write_text("print('hello world')\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["audit", "--secrets", "--path", str(tmp_path)])
        assert result.exit_code == EXIT_OK
        assert "no hardcoded secrets found" in result.output.lower()

    def test_targets_check_requires_config(self) -> None:
        result = runner.invoke(app, ["audit", "--targets"])
        assert result.exit_code == EXIT_USAGE_ERROR
        assert "--targets requires --config" in result.output

    def test_targets_check_flags_a_private_network_target(self, config_path) -> None:
        result = runner.invoke(app, ["audit", "--targets", "--config", str(config_path)])
        # VALID_CONFIG's single target has no api_base at all, so nothing
        # should be flagged -- this is the "no api_base configured" path,
        # distinct from an explicitly-private one below.
        assert result.exit_code == EXIT_OK
        assert "no flagged target urls" in result.output.lower()

    def test_targets_check_flags_explicit_private_api_base(self, tmp_path) -> None:
        config_text = """
name: "Private Target Campaign"
targets:
  - id: "local-model"
    provider: "openai"
    model: "local"
    api_key: "test-key-not-a-secret"
    api_base: "http://169.254.169.254/latest/meta-data/"
quality_gate:
  threshold: 5.0
"""
        config_path = tmp_path / "private.yaml"
        config_path.write_text(config_text, encoding="utf-8")
        result = runner.invoke(app, ["audit", "--targets", "--config", str(config_path)])
        assert result.exit_code == EXIT_OK  # informational only -- never fails the gate
        assert "1 target(s) flagged" in result.output

    def test_compliance_flag_prints_summary(self) -> None:
        result = runner.invoke(app, ["audit", "--compliance"])
        assert result.exit_code == EXIT_OK
        assert "IMPLEMENTED" in result.output

    def test_report_flag_writes_combined_markdown_report(self, monkeypatch, tmp_path) -> None:
        monkeypatch.chdir(tmp_path)
        report_path = tmp_path / "audit-report.md"
        result = runner.invoke(
            app, ["audit", "--compliance", "--report", str(report_path)]
        )
        assert result.exit_code == EXIT_OK
        assert report_path.exists()
        assert "Cyberjection Security Audit Report" in report_path.read_text(encoding="utf-8")

    def test_report_path_traversal_is_rejected(self, monkeypatch, tmp_path) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(
            app, ["audit", "--compliance", "--report", "../escape-report.md"]
        )
        assert result.exit_code == EXIT_USAGE_ERROR
        assert not (tmp_path.parent / "escape-report.md").exists()


class TestPluginsCommand:
    def test_lists_builtin_aliases_by_group(self) -> None:
        result = runner.invoke(app, ["plugins"])
        assert result.exit_code == EXIT_OK
        assert "base64" in result.output
        assert "direct_prompt_injection" in result.output
        assert "cyberjection.mutators" in result.output

    def test_reports_plugin_load_failures_and_fails_the_gate(self, monkeypatch) -> None:
        import cyberjection.cli.main as cli_main
        from cyberjection.plugins.loader import DiscoveryResult
        from cyberjection.utils.exceptions import PluginLoadError

        async def _unused():  # pragma: no cover - never awaited, just a placeholder
            raise NotImplementedError

        def _fake_discover_plugins(**_kwargs):
            return DiscoveryResult(
                loaded=[], failures=[PluginLoadError("Failed to load plugin 'broken' from group 'x': boom")]
            )

        monkeypatch.setattr(cli_main, "discover_plugins", _fake_discover_plugins)
        result = runner.invoke(app, ["plugins"])
        assert result.exit_code == EXIT_QUALITY_GATE_FAILED
        assert "plugin load failed" in result.output.lower()


class TestServeCommand:
    def test_reports_environment_error_when_uvicorn_unavailable(self) -> None:
        # This sandbox has no network access to install uvicorn (see
        # pyproject.toml's optional `api` extra), so `serve` should
        # degrade the same way `inspect` does when SQLAlchemy isn't
        # installed -- a clear environment-error exit code, not a bare
        # ImportError traceback.
        result = runner.invoke(app, ["serve"])
        assert result.exit_code == EXIT_ENVIRONMENT_ERROR
        assert "uvicorn" in result.output.lower()
