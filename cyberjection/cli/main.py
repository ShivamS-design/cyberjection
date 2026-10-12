"""Command Line Interface Engine (Phase 6): `run`, `inspect`, and `export`
entrypoints for executing evaluation runs, browsing persisted scan
history, and re-exporting a prior run's JSON report into another format.
Phase 8 adds `audit` (dependency/secret/target-URL auditing plus the
compliance control report) and wires every command through the
hash-chained audit log and the output-path/target-URL hardening checks
from `cyberjection.security`. Phase 9 replaces `run`'s hardcoded
two-`Finding` stub with `cyberjection.orchestrator.execute_campaign`,
which runs the campaign's test cases (scoped to `--target`) through the
real Phase 1-5 attack/evaluator stack and the Phase 4 persistence layer.
Phase 10 adds `plugins` (lists every registered mutator/strategy/evaluator/
exporter alias, discovering third-party ones via
`cyberjection.plugins.loader`) and `serve` (runs the dashboard API from
`cyberjection.api` under `uvicorn`, for `apps/dashboard` to talk to).
Phase 11 adds the `hubguard` command group (`scan`, `gate`, `file`,
`manifest`) for model supply-chain auditing, and makes `run` audit a
`huggingface` target under the campaign's `hubguard:` policy before any
prompt is sent.

Built on `typer` (declarative commands) and `rich` (table/console
rendering) per Task 6.1 of the Phase 6 design spec; both were already
declared project dependencies as of Phase 1's `pyproject.toml`
(`typer>=0.12`, `rich>=13.7`), anticipating this phase.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional, Tuple

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from cyberjection.config.loader import load_config
from cyberjection.config.schema import CampaignConfig, ProviderType, TargetConfig
from cyberjection.hubguard.transport import HubAccessError
from cyberjection.orchestrator import execute_campaign
from cyberjection.plugins import discover_plugins, known_aliases_by_group
from cyberjection.reporting import (
    Finding,
    JSONExporter,
    MarkdownExporter,
    QualityGateResult,
    SARIFReporter,
    evaluate_quality_gate,
    resolve_threshold,
)
from cyberjection.reporting import registry as exporter_registry
from cyberjection.security.audit_log import AuditLogger
from cyberjection.security.compliance import compliance_summary, generate_compliance_report
from cyberjection.security.dependency_audit import evaluate_dependency_gate, run_dependency_audit
from cyberjection.security.input_validation import assert_safe_output_path, assert_safe_target_url
from cyberjection.security.secrets_audit import (
    scan_campaign_config_for_hardcoded_secrets,
    scan_paths_for_secrets,
)
if TYPE_CHECKING:
    from cyberjection.hubguard.models import HubGuardReport
from cyberjection.utils.exceptions import (
    BudgetExceededError,
    CampaignNotFoundError,
    ConfigValidationError,
    PathTraversalError,
    UnknownTargetError,
    UnsafeTargetURLError,
)

app = typer.Typer(
    name="cyberjection",
    help="Enterprise AI Security & Guardrail Evaluation Harness",
    add_completion=False,
)
console = Console()

# Overridable so a deployment can point audit logs at a durable/shared
# location; defaults alongside the SQLite results DB's own default
# directory, matching the `.cyberjection/` convention `DatabaseManager`
# already established.
_audit_logger = AuditLogger(os.environ.get("CYBERJECTION_AUDIT_LOG", ".cyberjection/audit.jsonl"))

# Exit codes, documented once here rather than as magic numbers scattered
# through each command: 0 success, 1 a quality-gate failure (the run
# executed correctly but findings breached the configured threshold), 2 a
# usage/configuration error (bad config file, unknown target id, missing
# input file) caught before any evaluation ran, 3 an environment error (a
# command's runtime dependency -- e.g. SQLAlchemy for `inspect` -- isn't
# installed).
EXIT_OK = 0
EXIT_QUALITY_GATE_FAILED = 1
EXIT_USAGE_ERROR = 2
EXIT_ENVIRONMENT_ERROR = 3
# Phase 11: a HubGuard supply-chain audit returned BLOCK. Distinct from 1
# so CI can tell "the model misbehaved" from "the model was never loaded".
EXIT_SUPPLY_CHAIN_BLOCKED = 4
# The campaign hit max_cost_cap before finishing. Reports still cover the
# tests that ran, but a partial run must never look like a clean pass.
EXIT_BUDGET_EXCEEDED = 5


def _safe_output_path(path: Path) -> Path:
    """Wraps `assert_safe_output_path` for CLI report-writing flags,
    converting `PathTraversalError` into the same usage-error exit path
    every other bad-input case in this CLI uses, rather than letting it
    surface as an unhandled traceback. Report paths are contained to the
    current working directory by default -- matching how this project's
    own CI workflow already writes `results.sarif`/`results.json`
    relative to the repo root, so this is a no-op for every existing
    documented usage."""

    try:
        return assert_safe_output_path(path, base_dir=Path.cwd())
    except PathTraversalError as exc:
        console.print(f"[bold red]Unsafe report path:[/bold red] {escape(str(exc))}")
        _audit_logger.log("cli.output_path_rejected", resource=str(path), outcome="denied")
        raise typer.Exit(code=EXIT_USAGE_ERROR)


def _resolve_target(config: CampaignConfig, target_id: str) -> TargetConfig:
    for target in config.targets:
        if target.id == target_id:
            return target
    known = ", ".join(sorted(t.id for t in config.targets)) or "<none configured>"
    raise UnknownTargetError(
        f"Unknown target id '{target_id}'. Known target ids: {known}", target_id=target_id
    )


async def _execute_pipeline(
    config: CampaignConfig,
    target: TargetConfig,
    *,
    db_url: Optional[str] = None,
    resume_campaign_id: Optional[str] = None,
) -> List[Finding]:
    """Runs `config`'s test cases through
    `cyberjection.orchestrator.execute_campaign`, scoped to the ones that
    target `target.id` -- matching `run_evaluation`'s own console message
    ("starting evaluation on target: ...") and its `--target` flag's
    documented meaning: which target within the config to evaluate, not
    "run every test case in the config regardless of target." A
    `CampaignConfig` can declare test cases against several targets at
    once (running the same seed prompts across a fleet of models being a
    normal use case), so scoping here rather than in the orchestrator
    keeps `CampaignOrchestrator` itself target-agnostic and reusable for a
    future "run everything" mode without this function changing shape.

    Replaced the two-`Finding` stub every phase from 2 through 8 left in
    place -- see this module's own history in CHANGELOG.md for why wiring
    it was deferred that long.
    """

    scoped_tests = [test_case for test_case in config.tests if test_case.target == target.id]
    if not scoped_tests:
        return []

    scoped_config = config.model_copy(update={"tests": scoped_tests})
    return await execute_campaign(
        scoped_config,
        db_url=db_url,
        resume_campaign_id=resume_campaign_id,
        max_concurrency=config.max_workers,
    )


def _render_summary_table(findings: List[Finding], gate: QualityGateResult) -> Table:
    table = Table(title="Evaluation Summary")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Category", style="magenta")
    table.add_column("Score", style="bold red")
    table.add_column("Status", style="green")

    for finding in findings:
        status = "[red]FAIL[/red]" if finding.score >= gate.threshold else "[green]PASS[/green]"
        table.add_row(escape(finding.rule_id), escape(finding.category), f"{finding.score:.1f}", status)

    return table


@app.command("run")
def run_evaluation(
    config_path: Path = typer.Option(
        Path("cyberjection.yaml"), "--config", "-c", help="Path to evaluation config file"
    ),
    target_id: str = typer.Option(..., "--target", "-t", help="Target model identifier or alias"),
    threshold: Optional[float] = typer.Option(
        None,
        "--threshold",
        help="Severity score failure threshold (0.0 - 10.0); overrides the "
        "campaign's quality_gate.threshold",
    ),
    sarif_out: Optional[Path] = typer.Option(
        None, "--sarif-out", help="Path to save SARIF 2.1.0 report"
    ),
    json_out: Optional[Path] = typer.Option(None, "--json-out", help="Path to save JSON report"),
    markdown_out: Optional[Path] = typer.Option(
        None, "--markdown-out", help="Path to save Markdown summary report"
    ),
    db_url: Optional[str] = typer.Option(
        None,
        "--db-url",
        help="Database URL for campaign persistence (defaults to the local SQLite results DB); "
        "ignored if SQLAlchemy/aiosqlite aren't installed",
    ),
    resume_campaign_id: Optional[str] = typer.Option(
        None,
        "--resume",
        help="Resume a previously interrupted campaign by its campaign id (see `cyberjection "
        "inspect`) instead of starting a new one",
    ),
) -> None:
    """Execute automated security evaluations against a specified target model."""

    _audit_logger.log("cli.run.invoked", resource=str(config_path), metadata={"target": target_id})

    try:
        config = load_config(config_path)
    except ConfigValidationError as exc:
        console.print(f"[bold red]Configuration error:[/bold red] {escape(str(exc))}")
        _audit_logger.log("cli.run.config_error", resource=str(config_path), outcome="failure")
        raise typer.Exit(code=EXIT_USAGE_ERROR)

    try:
        target = _resolve_target(config, target_id)
    except UnknownTargetError as exc:
        console.print(f"[bold red]Target error:[/bold red] {escape(str(exc))}")
        _audit_logger.log("cli.run.unknown_target", resource=target_id, outcome="failure")
        raise typer.Exit(code=EXIT_USAGE_ERROR)

    console.print(
        f"[bold blue]Cyberjection Engine[/bold blue] starting evaluation on target: "
        f"[yellow]{target.id}[/yellow]"
    )

    # Report output paths are validated up front, before any evaluation
    # work runs, so a rejected path fails fast rather than after spending
    # real target/judge calls on a run whose report can't be written.
    safe_sarif_out = _safe_output_path(sarif_out) if sarif_out else None
    safe_json_out = _safe_output_path(json_out) if json_out else None
    safe_markdown_out = _safe_output_path(markdown_out) if markdown_out else None

    if config.hubguard is not None and target.provider == ProviderType.HUGGINGFACE:
        _enforce_hubguard_gate(config, target)

    effective_threshold = resolve_threshold(threshold, config.quality_gate.threshold)
    budget_stop: Optional[BudgetExceededError] = None
    try:
        findings = asyncio.run(
            _execute_pipeline(config, target, db_url=db_url, resume_campaign_id=resume_campaign_id)
        )
    except BudgetExceededError as exc:
        budget_stop = exc
        findings = list(exc.findings)
        console.print(f"[bold yellow]Budget cap reached:[/bold yellow] {escape(str(exc))}")
        _audit_logger.log(
            "cli.run.budget_exceeded",
            resource=target.id,
            outcome="partial",
            metadata={"spent_usd": exc.spent_usd, "cap_usd": exc.cap_usd},
        )
    except CampaignNotFoundError as exc:
        console.print(f"[bold red]Cannot resume campaign:[/bold red] {escape(str(exc))}")
        _audit_logger.log(
            "cli.run.resume_not_found", resource=resume_campaign_id or "<none>", outcome="failure"
        )
        raise typer.Exit(code=EXIT_USAGE_ERROR)
    gate = evaluate_quality_gate(findings, effective_threshold)

    console.print(_render_summary_table(findings, gate))

    if safe_sarif_out:
        SARIFReporter.export(findings, safe_sarif_out, threshold=effective_threshold)
        console.print(f"[bold green]SARIF report written to:[/bold green] {escape(str(safe_sarif_out))}")
    if safe_json_out:
        JSONExporter.export(findings, safe_json_out, threshold=effective_threshold)
        console.print(f"[bold green]JSON report written to:[/bold green] {escape(str(safe_json_out))}")
    if safe_markdown_out:
        MarkdownExporter.export(findings, safe_markdown_out, threshold=effective_threshold)
        console.print(f"[bold green]Markdown report written to:[/bold green] {escape(str(safe_markdown_out))}")

    _audit_logger.log(
        "cli.run.quality_gate",
        resource=target.id,
        outcome="pass" if gate.passed else "fail",
        metadata={"max_score": gate.max_score, "threshold": gate.threshold},
    )

    if not gate.passed:
        console.print(
            f"[bold red]QUALITY GATE FAILED:[/bold red] max score {gate.max_score:.1f} "
            f"meets or exceeds threshold {gate.threshold:.1f}"
        )
        raise typer.Exit(code=EXIT_QUALITY_GATE_FAILED)

    if budget_stop is not None:
        console.print(
            "[bold yellow]INCOMPLETE:[/bold yellow] the campaign stopped at its budget cap; "
            "raise max_cost_cap or narrow the campaign to evaluate every test."
        )
        raise typer.Exit(code=EXIT_BUDGET_EXCEEDED)

    console.print("[bold green]QUALITY GATE PASSED[/bold green]")
    raise typer.Exit(code=EXIT_OK)


async def _inspect_async(db_url: Optional[str], limit: int) -> List[Tuple[str, str, str, str]]:
    from cyberjection.persistence import CampaignRepository, DatabaseManager, DEFAULT_DB_URL

    manager = DatabaseManager(db_url or DEFAULT_DB_URL)
    await manager.init_db()
    rows: List[Tuple[str, str, str, str]] = []
    async with manager.session() as session:
        repo = CampaignRepository(session)
        campaigns = await repo.list_recent_campaigns(limit=limit)
        for campaign in campaigns:
            rows.append((campaign.id, campaign.name, campaign.status, str(campaign.started_at)))
    await manager.close()
    return rows


@app.command("inspect")
def inspect_history(
    db_url: Optional[str] = typer.Option(
        None,
        "--db-url",
        help="Database URL (defaults to the local SQLite results DB used by the persistence layer)",
    ),
    limit: int = typer.Option(10, "--limit", help="Maximum number of campaigns to list"),
) -> None:
    """Inspect persisted campaign scan history from the local results database."""

    from cyberjection.persistence import _SQLALCHEMY_AVAILABLE

    _audit_logger.log("cli.inspect.invoked", resource=db_url or "<default>", metadata={"limit": limit})

    if not _SQLALCHEMY_AVAILABLE:
        console.print(
            "[bold red]Persistence layer unavailable:[/bold red] SQLAlchemy/aiosqlite "
            "are not installed, so there is no scan history to inspect."
        )
        _audit_logger.log("cli.inspect.unavailable", outcome="failure")
        raise typer.Exit(code=EXIT_ENVIRONMENT_ERROR)

    rows = asyncio.run(_inspect_async(db_url, limit))

    table = Table(title="Recent Campaigns")
    table.add_column("Campaign ID", style="cyan")
    table.add_column("Name", style="magenta")
    table.add_column("Status", style="yellow")
    table.add_column("Started At", style="green")
    for campaign_id, name, status, started_at in rows:
        table.add_row(campaign_id, name, status, started_at)

    console.print(table)
    if not rows:
        console.print("[dim]No campaigns found.[/dim]")
    _audit_logger.log("cli.inspect.completed", outcome="success", metadata={"rows": len(rows)})
    raise typer.Exit(code=EXIT_OK)


@app.command("export")
def export_report(
    from_json: Path = typer.Option(
        ..., "--from-json", help="Path to a JSON report previously written by `run --json-out`"
    ),
    output_path: Path = typer.Option(
        ..., "--output", "-o", help="Path to write the converted report to"
    ),
    output_format: str = typer.Option(
        "sarif", "--format", "-f", help="Output format: 'sarif' or 'markdown'"
    ),
    threshold: float = typer.Option(
        7.0, "--threshold", help="Threshold to use when computing severity in the converted report"
    ),
) -> None:
    """Re-export a previously generated JSON report into SARIF or Markdown."""

    _audit_logger.log("cli.export.invoked", resource=str(from_json), metadata={"format": output_format})

    if not from_json.exists():
        console.print(f"[bold red]Input file not found:[/bold red] {escape(str(from_json))}")
        _audit_logger.log("cli.export.input_missing", resource=str(from_json), outcome="failure")
        raise typer.Exit(code=EXIT_USAGE_ERROR)

    safe_output_path = _safe_output_path(output_path)

    payload = json.loads(from_json.read_text(encoding="utf-8"))
    findings = [Finding.model_validate(item) for item in payload.get("findings", [])]

    if output_format == "sarif":
        SARIFReporter.export(findings, safe_output_path, threshold=threshold)
    elif output_format == "markdown":
        MarkdownExporter.export(findings, safe_output_path, threshold=threshold)
    elif exporter_registry.is_registered(output_format):
        # A plugin-registered format (see `cyberjection.plugins.loader` and
        # the ``cyberjection.exporters`` entry-point group) -- not one of
        # the two built-ins handled above, but discovered and registered
        # the same way at process startup.
        exporter_cls = exporter_registry.get_exporter_class(output_format)
        exporter_cls.export(findings, safe_output_path, threshold=threshold)
    else:
        known = ", ".join(sorted({"sarif", "markdown"} | set(exporter_registry.list_exporter_aliases())))
        console.print(
            f"[bold red]Unsupported format:[/bold red] '{output_format}' (known formats: {known})"
        )
        _audit_logger.log("cli.export.unsupported_format", resource=output_format, outcome="failure")
        raise typer.Exit(code=EXIT_USAGE_ERROR)

    console.print(f"[bold green]{output_format.upper()} report written to:[/bold green] {escape(str(safe_output_path))}")
    _audit_logger.log("cli.export.completed", resource=str(safe_output_path), outcome="success")
    raise typer.Exit(code=EXIT_OK)


@app.command("audit")
def run_audit(
    config_path: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Campaign config file to check for hardcoded secrets/unsafe target URLs"
    ),
    check_deps: bool = typer.Option(
        False, "--deps", help="Run a dependency vulnerability audit via pip-audit"
    ),
    check_secrets: bool = typer.Option(
        False, "--secrets", help="Scan --path location(s) (and --config, if given) for hardcoded credentials"
    ),
    check_targets: bool = typer.Option(
        False, "--targets", help="Check --config's targets for unsafe/private-network URLs (informational only)"
    ),
    scan_paths: Optional[List[Path]] = typer.Option(
        None, "--path", help="Path to scan for secrets; repeatable. Defaults to the current directory."
    ),
    show_compliance: bool = typer.Option(
        False, "--compliance", help="Print the OWASP ASVS / SOC 2 control self-assessment summary"
    ),
    report_out: Optional[Path] = typer.Option(
        None, "--report", help="Write a combined Markdown audit report to this path"
    ),
    fail_on_unavailable: bool = typer.Option(
        False,
        "--fail-on-unavailable",
        help="Fail the dependency gate if pip-audit isn't installed (recommended for CI)",
    ),
) -> None:
    """Run security-hardening checks: dependency vulnerabilities, hardcoded
    secrets, target URL safety, and/or the compliance control summary.

    With no check flags given at all, runs `--deps` and `--secrets` (over
    the current directory) as a sane default local audit -- a bare
    `cyberjection audit` does something useful rather than nothing. The
    `--targets` check is informational only: it never fails the overall
    gate, since private/localhost target URLs are a normal and expected
    configuration for local model servers (Ollama, vLLM, etc.), not a
    finding in themselves -- see `docs/COMPLIANCE.md`'s ASVS-V9.1 note.
    """

    _audit_logger.log(
        "cli.audit.invoked",
        metadata={
            "deps": check_deps,
            "secrets": check_secrets,
            "targets": check_targets,
            "compliance": show_compliance,
        },
    )

    if not any([check_deps, check_secrets, check_targets, show_compliance]):
        check_deps = True
        check_secrets = True

    report_sections: List[str] = []
    overall_ok = True

    if check_deps:
        console.print("[bold blue]Running dependency vulnerability audit...[/bold blue]")
        dep_report = run_dependency_audit()
        gate_passed = evaluate_dependency_gate(dep_report, fail_on_unavailable=fail_on_unavailable)
        overall_ok = overall_ok and gate_passed
        if dep_report.source == "unavailable":
            console.print(f"[yellow]Dependency audit unavailable:[/yellow] {escape(str(dep_report.detail))}")
        elif dep_report.findings:
            console.print(f"[bold red]{len(dep_report.findings)} vulnerable dependencies found:[/bold red]")
            for finding in dep_report.findings:
                console.print(
                    f"  - {escape(str(finding.package))} {escape(str(finding.installed_version))}: "
                    f"{escape(str(finding.advisory_id))} ({escape(str(finding.summary))})"
                )
        else:
            console.print(
                f"[bold green]No known vulnerabilities found[/bold green] "
                f"({dep_report.packages_checked} packages checked via {dep_report.source})."
            )
        _audit_logger.log(
            "cli.audit.deps",
            outcome="pass" if gate_passed else "fail",
            metadata={"source": dep_report.source, "findings": len(dep_report.findings)},
        )
        report_sections.append(
            f"## Dependency Audit\n\nSource: `{dep_report.source}`  \n"
            f"Packages checked: {dep_report.packages_checked}  \nFindings: {len(dep_report.findings)}\n"
        )

    if check_secrets:
        targets = scan_paths or [Path(".")]
        console.print(
            f"[bold blue]Scanning for hardcoded secrets in:[/bold blue] "
            f"{', '.join(str(p) for p in targets)}"
        )
        findings = scan_paths_for_secrets(targets)
        if config_path and config_path.exists():
            findings += scan_campaign_config_for_hardcoded_secrets(
                config_path.read_text(encoding="utf-8"), source_label=str(config_path)
            )
        overall_ok = overall_ok and not findings
        if findings:
            console.print(f"[bold red]{len(findings)} potential secret(s) found:[/bold red]")
            for secret in findings:
                console.print(
                    f"  - {escape(str(secret.source))}:{escape(str(secret.line))} [{escape(str(secret.severity))}] "
                    f"{escape(str(secret.pattern_name))} -> {escape(str(secret.excerpt))}"
                )
        else:
            console.print("[bold green]No hardcoded secrets found.[/bold green]")
        _audit_logger.log(
            "cli.audit.secrets", outcome="pass" if not findings else "fail", metadata={"findings": len(findings)}
        )
        report_sections.append(
            f"## Secrets Scan\n\nPaths scanned: {', '.join(str(p) for p in targets)}  \n"
            f"Findings: {len(findings)}\n"
        )

    if check_targets:
        if not config_path:
            console.print("[bold red]--targets requires --config[/bold red]")
            raise typer.Exit(code=EXIT_USAGE_ERROR)
        try:
            target_config = load_config(config_path)
        except ConfigValidationError as exc:
            console.print(f"[bold red]Configuration error:[/bold red] {escape(str(exc))}")
            raise typer.Exit(code=EXIT_USAGE_ERROR)
        console.print("[bold blue]Checking target URLs...[/bold blue]")
        flagged: List[str] = []
        for target in target_config.targets:
            api_base = target.api_base
            if not api_base:
                continue
            try:
                assert_safe_target_url(api_base)
            except UnsafeTargetURLError as exc:
                flagged.append(f"{target.id}: {exc}")
        if flagged:
            console.print(
                f"[yellow]{len(flagged)} target(s) flagged (informational -- private/local "
                f"network targets are a normal dev configuration):[/yellow]"
            )
            for line in flagged:
                console.print(f"  - {escape(str(line))}")
        else:
            console.print("[bold green]No flagged target URLs.[/bold green]")
        _audit_logger.log(
            "cli.audit.targets", outcome="flagged" if flagged else "pass", metadata={"flagged": len(flagged)}
        )
        report_sections.append(f"## Target URL Check (informational)\n\nFlagged: {len(flagged)}\n")

    if show_compliance:
        summary = compliance_summary()
        console.print(f"[bold blue]Compliance control summary:[/bold blue] {summary}")
        report_sections.append(generate_compliance_report())

    if report_out:
        safe_report_out = _safe_output_path(report_out)
        safe_report_out.parent.mkdir(parents=True, exist_ok=True)
        safe_report_out.write_text(
            "# Cyberjection Security Audit Report\n\n" + "\n".join(report_sections), encoding="utf-8"
        )
        console.print(f"[bold green]Audit report written to:[/bold green] {escape(str(safe_report_out))}")

    _audit_logger.log("cli.audit.completed", outcome="pass" if overall_ok else "fail")

    if not overall_ok:
        raise typer.Exit(code=EXIT_QUALITY_GATE_FAILED)
    raise typer.Exit(code=EXIT_OK)


@app.command("plugins")
def list_plugins() -> None:
    """List every registered mutator/strategy/evaluator/exporter alias,
    including third-party plugins discovered via `cyberjection.plugins`'s
    entry-point groups (``cyberjection.mutators``, ``cyberjection.strategies``,
    ``cyberjection.evaluators``, ``cyberjection.exporters``).

    Discovery is best-effort: a plugin that fails to load is reported in
    its own section rather than aborting the whole listing (see
    `cyberjection.plugins.loader`'s module docstring).
    """

    _audit_logger.log("cli.plugins.invoked")

    discovery = discover_plugins()
    for failure in discovery.failures:
        console.print(f"[bold red]Plugin load failed:[/bold red] {escape(str(failure))}")

    aliases_by_group = known_aliases_by_group()
    table = Table(title="Registered Plugins")
    table.add_column("Group", style="cyan")
    table.add_column("Aliases", style="magenta")
    for group in sorted(aliases_by_group):
        aliases = aliases_by_group[group]
        table.add_row(group, ", ".join(aliases) if aliases else "[dim]none[/dim]")
    console.print(table)

    if discovery.loaded:
        console.print(
            f"[bold green]{len(discovery.loaded)} third-party plugin(s) discovered "
            "and registered this run.[/bold green]"
        )

    _audit_logger.log(
        "cli.plugins.completed",
        outcome="pass" if not discovery.failures else "partial",
        metadata={"discovered": len(discovery.loaded), "failures": len(discovery.failures)},
    )
    if discovery.failures:
        raise typer.Exit(code=EXIT_QUALITY_GATE_FAILED)
    raise typer.Exit(code=EXIT_OK)


@app.command("serve")
def serve_dashboard_api(
    host: str = typer.Option("127.0.0.1", "--host", help="Interface to bind the dashboard API to"),
    port: int = typer.Option(8000, "--port", help="Port to bind the dashboard API to"),
    db_url: Optional[str] = typer.Option(
        None,
        "--db-url",
        help="Database URL the API reads campaign history from (defaults to the local SQLite "
        "results DB); ignored if SQLAlchemy/aiosqlite aren't installed",
    ),
    dashboard_dir: Optional[Path] = typer.Option(
        None,
        "--dashboard-dir",
        envvar="CYBERJECTION_DASHBOARD_DIR",
        help="Also serve the built web dashboard (apps/dashboard/dist) from the same origin",
    ),
) -> None:
    """Serve the Phase 10 dashboard REST API (`cyberjection.api`) for
    `apps/dashboard` -- or any other HTTP client -- to consume.

    Requires `uvicorn` (the optional `api` extra: `pip install
    cyberjection[api]`); building the API application itself has no such
    requirement, only actually serving HTTP connections over a socket
    does. Blocks until interrupted.
    """

    from cyberjection.api.server import UvicornUnavailableError, run_server
    from cyberjection.api.static import DashboardNotBuiltError

    _audit_logger.log("cli.serve.invoked", metadata={"host": host, "port": port})
    console.print(f"[bold blue]Cyberjection dashboard API[/bold blue] starting on {host}:{port}")
    if dashboard_dir is not None:
        console.print(f"[bold blue]Serving dashboard from[/bold blue] {escape(str(dashboard_dir))}")
    try:
        run_server(host=host, port=port, db_url=db_url, dashboard_dir=str(dashboard_dir) if dashboard_dir else None)
    except DashboardNotBuiltError as exc:
        console.print(f"[bold red]Cannot serve dashboard:[/bold red] {escape(str(exc))}")
        _audit_logger.log("cli.serve.dashboard_missing", outcome="failure")
        raise typer.Exit(code=EXIT_USAGE_ERROR)
    except UvicornUnavailableError as exc:
        console.print(f"[bold red]Cannot start server:[/bold red] {escape(str(exc))}")
        _audit_logger.log("cli.serve.unavailable", outcome="failure")
        raise typer.Exit(code=EXIT_ENVIRONMENT_ERROR)


# --- Phase 11: HubGuard ------------------------------------------------------------

hubguard_app = typer.Typer(
    name="hubguard",
    help="Model supply-chain security: audit Hugging Face repositories before loading them.",
    add_completion=False,
)
app.add_typer(hubguard_app, name="hubguard")

_SEVERITY_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
_VERDICT_STYLE = {"PASS": "bold green", "WARN": "bold yellow", "BLOCK": "bold red"}


def _render_hubguard_report(report: "HubGuardReport") -> None:
    commit = f" @ {report.commit_sha[:12]}" if report.commit_sha else f" @ {report.revision}"
    console.print(f"[bold blue]Repository:[/bold blue] {escape(str(report.repo_id))}{escape(str(commit))}")
    verdict = report.verdict.value
    style = _VERDICT_STYLE[verdict]
    console.print(f"[bold]Safety Verdict:[/bold] [{style}]{verdict}[/{style}]")
    console.print(f"[bold]Risk Score:[/bold] {report.risk_score}/10 (policy ceiling {report.max_allowed_risk_score})")
    if report.incomplete:
        console.print("[bold red]Scan incomplete:[/bold red] some files could not be verified (fail-closed).")
    if not report.findings:
        console.print("[bold green]No findings.[/bold green]")
        return
    table = Table(title=f"HubGuard Findings ({len(report.findings)})")  # count only: safe
    table.add_column("Severity")
    table.add_column("Category", style="magenta")
    table.add_column("File", style="cyan")
    table.add_column("Description")
    for finding in report.findings:
        sev = finding.severity.value
        location = (finding.file or "-") + (f":{finding.line}" if finding.line else "")
        table.add_row(
            f"[{_SEVERITY_STYLE[sev]}]{sev.upper()}[/{_SEVERITY_STYLE[sev]}]",
            finding.category.value,
            escape(location),
            escape(finding.description),
        )
    console.print(table)


def _write_hubguard_outputs(
    report: "HubGuardReport",
    json_out: Optional[Path],
    sarif_out: Optional[Path],
    markdown_out: Optional[Path],
) -> None:
    findings = report.to_reporting_findings()
    if json_out:
        path = _safe_output_path(json_out)
        path.write_text(report.to_json(), encoding="utf-8")
        console.print(f"[bold green]HubGuard JSON report written to:[/bold green] {escape(str(path))}")
    if sarif_out:
        path = _safe_output_path(sarif_out)
        SARIFReporter.export(findings, path, threshold=report.max_allowed_risk_score)
        console.print(f"[bold green]SARIF report written to:[/bold green] {escape(str(path))}")
    if markdown_out:
        path = _safe_output_path(markdown_out)
        MarkdownExporter.export(findings, path, threshold=report.max_allowed_risk_score)
        console.print(f"[bold green]Markdown report written to:[/bold green] {escape(str(path))}")


def _enforce_hubguard_gate(config: CampaignConfig, target: TargetConfig) -> None:
    from cyberjection.hubguard.gate import gate_campaign

    console.print(
        f"[bold blue]HubGuard[/bold blue] auditing model repository for target [yellow]{target.id}[/yellow]..."
    )
    result = asyncio.run(gate_campaign(config, target_ids=[target.id], audit_logger=_audit_logger))
    for report in result.reports.values():
        _render_hubguard_report(report)
    if result.blocked:
        console.print("[bold red]SUPPLY-CHAIN GATE BLOCKED:[/bold red] the campaign was not started.")
        _audit_logger.log("cli.run.hubguard_blocked", resource=target.id, outcome="fail")
        raise typer.Exit(code=EXIT_SUPPLY_CHAIN_BLOCKED)


def _exit_for_report(report: "HubGuardReport") -> None:
    raise typer.Exit(code=EXIT_SUPPLY_CHAIN_BLOCKED if report.blocked else EXIT_OK)


@hubguard_app.command("scan")
def hubguard_scan(
    repo_id: str = typer.Argument(..., help="Hugging Face repo id, e.g. meta-llama/Llama-3-8B-Instruct"),
    revision: str = typer.Option("main", "--revision", "-r", help="Branch, tag or commit SHA to audit"),
    policy: str = typer.Option("strict", "--policy", help="SafeTensors enforcement: strict | warn | off"),
    block_remote_code: bool = typer.Option(False, "--block-remote-code", help="Block repos that need trust_remote_code"),
    allow_org: Optional[List[str]] = typer.Option(None, "--allow-org", help="Allowed organization; repeatable"),
    max_risk: float = typer.Option(7.0, "--max-risk", min=0.0, max=10.0, help="Risk score above which the verdict is BLOCK"),
    no_pickles: bool = typer.Option(False, "--no-pickles", help="Skip pickle opcode scanning"),
    no_remote_code: bool = typer.Option(False, "--no-remote-code", help="Skip remote code analysis"),
    no_secrets: bool = typer.Option(False, "--no-secrets", help="Skip secret scanning"),
    history_depth: int = typer.Option(10, "--history-depth", min=0, help="Earlier commits to scan for secrets"),
    manifest: Optional[Path] = typer.Option(None, "--manifest", help="SHA-256 HashManifest (YAML/JSON) to verify against"),
    verify_downloads: bool = typer.Option(False, "--verify-downloads", help="Stream weight files and verify their SHA-256"),
    profile_remote_code: bool = typer.Option(
        False, "--profile-remote-code", help="EXECUTES remote code in the restricted sandbox profiler (opt-in)"
    ),
    scan_weights: bool = typer.Option(False, "--scan-weights", help="Read tensors for anomaly statistics"),
    local_dir: Optional[Path] = typer.Option(None, "--local-dir", help="Scan a local snapshot directory instead of the Hub"),
    json_out: Optional[Path] = typer.Option(None, "--json-out", help="Write the full HubGuard JSON report"),
    sarif_out: Optional[Path] = typer.Option(None, "--sarif-out", help="Write a SARIF 2.1.0 report"),
    markdown_out: Optional[Path] = typer.Option(None, "--markdown-out", help="Write a Markdown report"),
) -> None:
    """Audit one model repository. Exits 0 (PASS/WARN), 4 (BLOCK), or 2 (usage error)."""

    from cyberjection.hubguard import EnforcementLevel, HubGuardClient

    _audit_logger.log("cli.hubguard.scan.invoked", resource=repo_id, metadata={"revision": revision})
    # Validate output paths before doing any network work.
    for out in (json_out, sarif_out, markdown_out):
        if out:
            _safe_output_path(out)
    try:
        client = HubGuardClient(
            repo_id,
            revision=revision,
            safetensors_policy=EnforcementLevel(policy.lower()),
            block_remote_code=block_remote_code,
            allowed_organizations=allow_org or None,
            max_allowed_risk_score=max_risk,
            scan_pickles=not no_pickles,
            scan_remote_code=not no_remote_code,
            scan_secrets=not no_secrets,
            history_depth=history_depth,
            manifest=manifest,
            verify_downloads=verify_downloads,
            profile_remote_code=profile_remote_code,
            scan_weights=scan_weights,
            local_dir=local_dir,
            audit_logger=_audit_logger,
        )
    except (ValueError, OSError, HubAccessError) as exc:
        console.print(f"[bold red]Usage error:[/bold red] {escape(str(exc))}")
        raise typer.Exit(code=EXIT_USAGE_ERROR)
    report = asyncio.run(client.audit_repository())
    _render_hubguard_report(report)
    _write_hubguard_outputs(report, json_out, sarif_out, markdown_out)
    _exit_for_report(report)


@hubguard_app.command("gate")
def hubguard_gate(
    config_path: Path = typer.Option(
        Path("cyberjection.yaml"), "--config", "-c", help="Campaign config with a hubguard section"
    ),
    target_id: Optional[List[str]] = typer.Option(None, "--target", "-t", help="Limit to these target ids; repeatable"),
) -> None:
    """Audit every `huggingface` target in a campaign under its `hubguard:` policy."""

    from cyberjection.hubguard.gate import gate_campaign

    try:
        config = load_config(config_path)
    except ConfigValidationError as exc:
        console.print(f"[bold red]Configuration error:[/bold red] {escape(str(exc))}")
        raise typer.Exit(code=EXIT_USAGE_ERROR)
    if config.hubguard is None:
        console.print("[bold red]Configuration error:[/bold red] the campaign has no `hubguard:` section.")
        raise typer.Exit(code=EXIT_USAGE_ERROR)
    result = asyncio.run(gate_campaign(config, target_ids=target_id or None, audit_logger=_audit_logger))
    for target, report in result.reports.items():
        console.rule(f"target: {escape(str(target))}")
        _render_hubguard_report(report)
    if result.skipped:
        console.print(f"[dim]Skipped non-huggingface targets: {escape(str(', '.join(result.skipped)))}[/dim]")
    if result.blocked:
        console.print(f"[bold red]GATE BLOCKED:[/bold red] {escape(str(', '.join(result.blocked_targets)))}")
        raise typer.Exit(code=EXIT_SUPPLY_CHAIN_BLOCKED)
    console.print("[bold green]GATE PASSED[/bold green]")
    raise typer.Exit(code=EXIT_OK)


@hubguard_app.command("file")
def hubguard_file(
    paths: List[Path] = typer.Argument(..., help="Local .bin/.pt/.pkl/.npy/.safetensors/.py files to scan"),
    max_risk: float = typer.Option(7.0, "--max-risk", min=0.0, max=10.0),
) -> None:
    """Statically scan local model files (never loads or executes them)."""

    from datetime import datetime, timezone

    from cyberjection.hubguard.models import HubGuardReport, ScannedFile
    from cyberjection.hubguard.picklescan import scan_pickle_file
    from cyberjection.hubguard.remotecode import analyze_python_source
    from cyberjection.hubguard.safetensors import validate_safetensors_file

    findings = []
    scanned = []
    for path in paths:
        if not path.is_file():
            console.print(f"[bold red]Not a file:[/bold red] {escape(str(path))}")
            raise typer.Exit(code=EXIT_USAGE_ERROR)
        suffix = path.suffix.lower()
        if suffix == ".safetensors":
            findings += validate_safetensors_file(path).findings
            kind = "safetensors"
        elif suffix == ".py":
            source = path.read_text(encoding="utf-8", errors="replace")
            findings += analyze_python_source(source, filename=path.name).findings
            kind = "code"
        else:
            result = scan_pickle_file(path)
            findings += result.findings
            kind = result.format
        scanned.append(ScannedFile(path=str(path), size=path.stat().st_size, kind=kind))
    report = HubGuardReport.build(
        repo_id="local-files",
        revision="local",
        commit_sha=None,
        findings=findings,
        files=scanned,
        max_allowed_risk_score=max_risk,
        started_at=datetime.now(timezone.utc),
        duration_seconds=0.0,
    )
    _render_hubguard_report(report)
    _audit_logger.log("cli.hubguard.file", outcome=report.verdict.value.lower(), metadata={"files": len(paths)})
    _exit_for_report(report)


@hubguard_app.command("manifest")
def hubguard_manifest(
    repo_id: str = typer.Argument(..., help="Hugging Face repo id"),
    output: Path = typer.Option(..., "--out", "-o", help="Where to write the manifest (.yaml or .json)"),
    revision: str = typer.Option("main", "--revision", "-r"),
    verify_downloads: bool = typer.Option(
        False, "--verify-downloads", help="Hash the actual bytes instead of trusting Hub LFS metadata"
    ),
    local_dir: Optional[Path] = typer.Option(None, "--local-dir", help="Hash a local snapshot directory instead"),
) -> None:
    """Pin the SHA-256 of every weight and code file at a revision."""

    from cyberjection.hubguard import HubGuardClient, generate_manifest

    safe_output = _safe_output_path(output)
    try:
        client = HubGuardClient(repo_id, revision=revision, verify_downloads=verify_downloads, local_dir=local_dir)
        manifest = asyncio.run(generate_manifest(client))
    except (ValueError, OSError, HubAccessError) as exc:
        console.print(f"[bold red]Error:[/bold red] {escape(str(exc))}")
        raise typer.Exit(code=EXIT_USAGE_ERROR)
    manifest.dump(safe_output)
    console.print(f"[bold green]Pinned {len(manifest.files)} file(s) to:[/bold green] {escape(str(safe_output))}")
    _audit_logger.log("cli.hubguard.manifest", resource=repo_id, metadata={"files": len(manifest.files)})
    raise typer.Exit(code=EXIT_OK)


if __name__ == "__main__":
    app()
