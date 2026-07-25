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
from typing import List, Optional, Tuple

import typer
from rich.console import Console
from rich.table import Table

from cyberjection.config.loader import load_config
from cyberjection.config.schema import CampaignConfig, TargetConfig
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
from cyberjection.utils.exceptions import (
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
        console.print(f"[bold red]Unsafe report path:[/bold red] {exc}")
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
        table.add_row(finding.rule_id, finding.category, f"{finding.score:.1f}", status)

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
        console.print(f"[bold red]Configuration error:[/bold red] {exc}")
        _audit_logger.log("cli.run.config_error", resource=str(config_path), outcome="failure")
        raise typer.Exit(code=EXIT_USAGE_ERROR)

    try:
        target = _resolve_target(config, target_id)
    except UnknownTargetError as exc:
        console.print(f"[bold red]Target error:[/bold red] {exc}")
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

    effective_threshold = resolve_threshold(threshold, config.quality_gate.threshold)
    try:
        findings = asyncio.run(
            _execute_pipeline(config, target, db_url=db_url, resume_campaign_id=resume_campaign_id)
        )
    except CampaignNotFoundError as exc:
        console.print(f"[bold red]Cannot resume campaign:[/bold red] {exc}")
        _audit_logger.log(
            "cli.run.resume_not_found", resource=resume_campaign_id or "<none>", outcome="failure"
        )
        raise typer.Exit(code=EXIT_USAGE_ERROR)
    gate = evaluate_quality_gate(findings, effective_threshold)

    console.print(_render_summary_table(findings, gate))

    if safe_sarif_out:
        SARIFReporter.export(findings, safe_sarif_out, threshold=effective_threshold)
        console.print(f"[bold green]SARIF report written to:[/bold green] {safe_sarif_out}")
    if safe_json_out:
        JSONExporter.export(findings, safe_json_out, threshold=effective_threshold)
        console.print(f"[bold green]JSON report written to:[/bold green] {safe_json_out}")
    if safe_markdown_out:
        MarkdownExporter.export(findings, safe_markdown_out, threshold=effective_threshold)
        console.print(f"[bold green]Markdown report written to:[/bold green] {safe_markdown_out}")

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
        console.print(f"[bold red]Input file not found:[/bold red] {from_json}")
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

    console.print(f"[bold green]{output_format.upper()} report written to:[/bold green] {safe_output_path}")
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
            console.print(f"[yellow]Dependency audit unavailable:[/yellow] {dep_report.detail}")
        elif dep_report.findings:
            console.print(f"[bold red]{len(dep_report.findings)} vulnerable dependencies found:[/bold red]")
            for finding in dep_report.findings:
                console.print(
                    f"  - {finding.package} {finding.installed_version}: "
                    f"{finding.advisory_id} ({finding.summary})"
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
            for finding in findings:
                console.print(
                    f"  - {finding.source}:{finding.line} [{finding.severity}] "
                    f"{finding.pattern_name} -> {finding.excerpt}"
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
            console.print(f"[bold red]Configuration error:[/bold red] {exc}")
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
                console.print(f"  - {line}")
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
        console.print(f"[bold green]Audit report written to:[/bold green] {safe_report_out}")

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
        console.print(f"[bold red]Plugin load failed:[/bold red] {failure}")

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
) -> None:
    """Serve the Phase 10 dashboard REST API (`cyberjection.api`) for
    `apps/dashboard` -- or any other HTTP client -- to consume.

    Requires `uvicorn` (the optional `api` extra: `pip install
    cyberjection[api]`); building the API application itself has no such
    requirement, only actually serving HTTP connections over a socket
    does. Blocks until interrupted.
    """

    from cyberjection.api.server import UvicornUnavailableError, run_server

    _audit_logger.log("cli.serve.invoked", metadata={"host": host, "port": port})
    console.print(f"[bold blue]Cyberjection dashboard API[/bold blue] starting on {host}:{port}")
    try:
        run_server(host=host, port=port, db_url=db_url)
    except UvicornUnavailableError as exc:
        console.print(f"[bold red]Cannot start server:[/bold red] {exc}")
        _audit_logger.log("cli.serve.unavailable", outcome="failure")
        raise typer.Exit(code=EXIT_ENVIRONMENT_ERROR)


if __name__ == "__main__":
    app()
