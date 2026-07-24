"""Command Line Interface Engine (Phase 6): `run`, `inspect`, and `export`
entrypoints for executing evaluation runs, browsing persisted scan
history, and re-exporting a prior run's JSON report into another format.

Built on `typer` (declarative commands) and `rich` (table/console
rendering) per Task 6.1 of the Phase 6 design spec; both were already
declared project dependencies as of Phase 1's `pyproject.toml`
(`typer>=0.12`, `rich>=13.7`), anticipating this phase.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import List, Optional, Tuple

import typer
from rich.console import Console
from rich.table import Table

from cyberjection.config.loader import load_config
from cyberjection.config.schema import CampaignConfig, TargetConfig
from cyberjection.reporting import (
    Finding,
    JSONExporter,
    MarkdownExporter,
    QualityGateResult,
    SARIFReporter,
    evaluate_quality_gate,
    resolve_threshold,
)
from cyberjection.utils.exceptions import ConfigValidationError, UnknownTargetError

app = typer.Typer(
    name="cyberjection",
    help="Enterprise AI Security & Guardrail Evaluation Harness",
    add_completion=False,
)
console = Console()

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


def _resolve_target(config: CampaignConfig, target_id: str) -> TargetConfig:
    for target in config.targets:
        if target.id == target_id:
            return target
    known = ", ".join(sorted(t.id for t in config.targets)) or "<none configured>"
    raise UnknownTargetError(
        f"Unknown target id '{target_id}'. Known target ids: {known}", target_id=target_id
    )


async def _execute_pipeline(config: CampaignConfig, target: TargetConfig) -> List[Finding]:
    """Stub evaluation pipeline bridge.

    Wiring `config`/`target` through the real Phase 2-5 attack/evaluator
    machinery (mutators, single-turn strategies, the cascade evaluator,
    Crescendo/TAP) into one orchestrated run is explicitly out of scope
    for every phase shipped so far -- Phase 4's and Phase 5's changelogs
    both note that no orchestrator loop exists yet, and this stub is where
    that wiring will eventually live. It stays `async` and shaped exactly
    like the eventual real implementation (same parameters, same return
    type) so a later phase only has to replace this function's body, not
    any of its callers.
    """

    return [
        Finding(
            rule_id="CJ-001",
            category="prompt_injection",
            score=2.1,
            details="Static prompt test passed.",
        ),
        Finding(
            rule_id="CJ-002",
            category="jailbreak_crescendo",
            score=3.4,
            details="Multi-turn escalation resisted.",
        ),
    ]


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
) -> None:
    """Execute automated security evaluations against a specified target model."""

    try:
        config = load_config(config_path)
    except ConfigValidationError as exc:
        console.print(f"[bold red]Configuration error:[/bold red] {exc}")
        raise typer.Exit(code=EXIT_USAGE_ERROR)

    try:
        target = _resolve_target(config, target_id)
    except UnknownTargetError as exc:
        console.print(f"[bold red]Target error:[/bold red] {exc}")
        raise typer.Exit(code=EXIT_USAGE_ERROR)

    console.print(
        f"[bold blue]Cyberjection Engine[/bold blue] starting evaluation on target: "
        f"[yellow]{target.id}[/yellow]"
    )

    effective_threshold = resolve_threshold(threshold, config.quality_gate.threshold)
    findings = asyncio.run(_execute_pipeline(config, target))
    gate = evaluate_quality_gate(findings, effective_threshold)

    console.print(_render_summary_table(findings, gate))

    if sarif_out:
        SARIFReporter.export(findings, sarif_out, threshold=effective_threshold)
        console.print(f"[bold green]SARIF report written to:[/bold green] {sarif_out}")
    if json_out:
        JSONExporter.export(findings, json_out, threshold=effective_threshold)
        console.print(f"[bold green]JSON report written to:[/bold green] {json_out}")
    if markdown_out:
        MarkdownExporter.export(findings, markdown_out, threshold=effective_threshold)
        console.print(f"[bold green]Markdown report written to:[/bold green] {markdown_out}")

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

    if not _SQLALCHEMY_AVAILABLE:
        console.print(
            "[bold red]Persistence layer unavailable:[/bold red] SQLAlchemy/aiosqlite "
            "are not installed, so there is no scan history to inspect."
        )
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

    if not from_json.exists():
        console.print(f"[bold red]Input file not found:[/bold red] {from_json}")
        raise typer.Exit(code=EXIT_USAGE_ERROR)

    payload = json.loads(from_json.read_text(encoding="utf-8"))
    findings = [Finding.model_validate(item) for item in payload.get("findings", [])]

    if output_format == "sarif":
        SARIFReporter.export(findings, output_path, threshold=threshold)
    elif output_format == "markdown":
        MarkdownExporter.export(findings, output_path, threshold=threshold)
    else:
        console.print(
            f"[bold red]Unsupported format:[/bold red] '{output_format}' "
            "(expected 'sarif' or 'markdown')"
        )
        raise typer.Exit(code=EXIT_USAGE_ERROR)

    console.print(f"[bold green]{output_format.upper()} report written to:[/bold green] {output_path}")
    raise typer.Exit(code=EXIT_OK)


if __name__ == "__main__":
    app()
