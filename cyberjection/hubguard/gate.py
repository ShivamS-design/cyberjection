"""Campaign-level supply-chain gate (Phase 11 <-> Phase 1/6 integration).

When a campaign declares a `hubguard:` section, every target whose
provider is `huggingface` is audited before the orchestrator sends it a
prompt; `cyberjection run` refuses to start the campaign if any audited
target is `BLOCK`ed (exit code `EXIT_SUPPLY_CHAIN_BLOCKED`). Targets from
other providers aren't model repositories and are skipped.

Static policy checks (remote code a policy forbids, organizations outside
the allowlist) already fail at config-load time in
`CampaignConfig.validate_hubguard_policy`; this module covers everything
that needs the repository's actual contents.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional

from cyberjection.config.schema import CampaignConfig, ProviderType, TargetConfig
from cyberjection.hubguard.client import HubGuardClient
from cyberjection.hubguard.models import HubGuardReport, Verdict
from cyberjection.hubguard.transport import repo_id_from_model


@dataclass
class GateResult:
    reports: Dict[str, HubGuardReport] = field(default_factory=dict)  # target id -> report
    skipped: List[str] = field(default_factory=list)  # non-huggingface target ids

    @property
    def blocked(self) -> bool:
        return any(r.verdict == Verdict.BLOCK for r in self.reports.values())

    @property
    def blocked_targets(self) -> List[str]:
        return [tid for tid, r in self.reports.items() if r.verdict == Verdict.BLOCK]


def hub_targets(config: CampaignConfig, target_ids: Optional[Iterable[str]] = None) -> List[TargetConfig]:
    wanted = set(target_ids) if target_ids is not None else None
    return [
        t for t in config.targets
        if t.provider == ProviderType.HUGGINGFACE and (wanted is None or t.id in wanted)
    ]


async def gate_campaign(
    config: CampaignConfig,
    *,
    target_ids: Optional[Iterable[str]] = None,
    client_factory: Optional[Callable[..., HubGuardClient]] = None,
    audit_logger: Any = None,
    **client_overrides: Any,
) -> GateResult:
    """Audits each in-scope `huggingface` target under the campaign's
    `hubguard` policy. A campaign without a `hubguard` section passes
    trivially with no reports."""

    result = GateResult()
    if config.hubguard is None:
        return result
    wanted = set(target_ids) if target_ids is not None else None
    for target in config.targets:
        if wanted is not None and target.id not in wanted:
            continue
        if target.provider != ProviderType.HUGGINGFACE:
            result.skipped.append(target.id)
            continue
        factory = client_factory or HubGuardClient.from_policy
        client = factory(
            repo_id_from_model(target.model),
            config.hubguard,
            revision=target.revision or "main",
            audit_logger=audit_logger,
            **client_overrides,
        )
        result.reports[target.id] = await client.audit_repository()
    return result
